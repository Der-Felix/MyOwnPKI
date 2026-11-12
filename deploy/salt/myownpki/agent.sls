{#-
  MyOwnPKI agent: verified package, root, enrollment, deployments (docs/PHASE3.md section 12).
  The pillar is myownpki:agent; see README.md and pillar.example.
  No service.running and no enabled unit on purpose: "setup" enables and starts the
  agent when the host is admitted, a host that waits for approval stays disabled.
-#}
{% from "myownpki/map.jinja" import m, errors with context %}
{% set bin = m['agent_bin'] %}
{% set list_guard %}{{ bin }} deployment list | awk -v n=@NAME@ 'NR > 1 && $1 == n { found = 1 } END { exit !found }'{% endset %}

{% if errors %}
{#- Fail closed. The reason is in the name: test=True hides the comment of this state. -#}
{% set reason = 'myownpki formula refused: ' ~ (errors | join('; ')) %}
myownpki-agent-refused:
  test.fail_without_changes:
    - name: {{ reason | yaml_dquote }}
    - comment: {{ reason | yaml_dquote }}
{% else %}

{% set setup_args = [
  bin, 'setup',
  '--server', m['server'] | quote,
  '--ca-bundle', m['root_path'] | quote,
  '--root-sha256', m['root_sha256'],
  '--package-format', m['package_format'],
  '--acme-directory', m['acme_directory'] | quote,
] %}
{% if m['webroot'] != '' %}
{%   set _ = setup_args.extend(['--webroot', m['webroot'] | quote]) %}
{% endif %}
{% if m['low_ports'] %}
{%   set _ = setup_args.append('--low-ports') %}
{% endif %}
{#- The first enrollment gets the pass as a file, never as a value. -#}
{% set setup_enroll = (setup_args + (['--token-file', m['token_file'] | quote] if m['pass_set'] else [])) | join(' ') %}
{% set setup_update = setup_args | join(' ') %}

myownpki-agent-cache:
  file.directory:
    - name: {{ m['cache_dir'] }}
    - user: root
    - group: root
    - mode: '0755'
    - makedirs: True

# The package is staged, hash-checked and only then installed from that local file.
# Salt ignores source_hash for salt:// sources, so the check below is explicit.
myownpki-agent-package-file:
  file.managed:
    - name: {{ m['package_path'] }}
    - source: {{ m['package_source'] | yaml_dquote }}
{% if m['package_source'].startswith('https://') %}
    - source_hash: sha256={{ m['package_sha256'] }}
{% endif %}
    - user: root
    - group: root
    - mode: '0644'
    - require:
      - file: myownpki-agent-cache

# Runs only when the file does not match the hash from the admin UI, and then fails.
myownpki-agent-package-verified:
  cmd.run:
    - name: {{ ('echo ' ~ (('myownpki: SHA-256 of ' ~ m['package_path'] ~ ' does not match package.sha256.' ~ m['arch'] ~ '; not installing') | quote) ~ ' >&2; exit 1') | yaml_dquote }}
    - unless: {{ ('echo ' ~ ((m['package_sha256'] ~ '  ' ~ m['package_path']) | quote) ~ ' | sha256sum -c --status -') | yaml_dquote }}
    - require:
      - file: myownpki-agent-package-file

myownpki-agent-package:
  pkg.installed:
    - sources:
      - myownpki-agent: {{ m['package_path'] }}
    - require:
      - cmd: myownpki-agent-package-verified

# setup compares the DER SHA-256 of this file with --root-sha256 and refuses a mismatch.
myownpki-agent-root:
  file.managed:
    - name: {{ m['root_path'] }}
    - source: {{ m['root_source'] | yaml_dquote }}
    - user: root
    - group: root
    - mode: '0644'
    - require:
      - file: myownpki-agent-cache

{% if m['pass_set'] %}
# The pass is a secret: read from the pillar by Salt, never part of a command or a name.
# Only while the host has no agent certificate; setup deletes the file on admission.
myownpki-agent-pass:
  file.managed:
    - name: {{ m['token_file'] }}
    - contents_pillar: myownpki:agent:enrollment_pass
    - user: root
    - group: root
    - mode: '0600'
    - show_changes: False
    - unless: test -e {{ m['agent_crt'] }}
{% endif %}

{% if m['config_source'] != '' %}
# One owner of agent.yaml: this file. setup keeps a customized file.
myownpki-agent-config:
  file.managed:
    - name: {{ m['config_path'] }}
    - source: {{ m['config_source'] | yaml_dquote }}
    - user: root
    - group: root
    - mode: '0644'
    - makedirs: True
    - require:
      - pkg: myownpki-agent-package
{% endif %}

# A new package on an enrolled host: run setup again, as the update instructions say
# (it refreshes the unit and drop-ins and restarts the agent). Not on a new host.
myownpki-agent-setup-update:
  cmd.run:
    - name: {{ setup_update | yaml_dquote }}
    - onlyif: test -e {{ m['agent_crt'] }}
    - onchanges:
      - pkg: myownpki-agent-package
    - timeout: 180
    - require:
      - pkg: myownpki-agent-package
      - file: myownpki-agent-root
{% if m['config_source'] != '' %}
      - file: myownpki-agent-config
{% endif %}

# Enrollment. creates: the host has its certificate. A host that waits for approval
# runs this again on the next highstate and polls the request.
myownpki-agent-setup:
  cmd.run:
    - name: {{ setup_enroll | yaml_dquote }}
    - creates: {{ m['agent_crt'] }}
    - timeout: 180
    - require:
      - pkg: myownpki-agent-package
      - file: myownpki-agent-root
      - cmd: myownpki-agent-setup-update
{% if m['pass_set'] %}
      - file: myownpki-agent-pass
{% endif %}
{% if m['config_source'] != '' %}
      - file: myownpki-agent-config
{% endif %}

{% set restart_on = [] %}

{% if m['config_source'] != '' %}
myownpki-agent-sandbox:
  cmd.run:
    - name: {{ bin }} sandbox sync
    - onchanges:
      - file: myownpki-agent-config
    - require:
      - cmd: myownpki-agent-setup
{% set _ = restart_on.append('myownpki-agent-config') %}
{% endif %}

{% for a in m['absent'] %}
myownpki-agent-deployment-absent-{{ a }}:
  cmd.run:
    - name: {{ (bin ~ ' deployment remove ' ~ (a | quote)) | yaml_dquote }}
    - onlyif: {{ list_guard | replace('@NAME@', a | quote) | yaml_dquote }}
    - require:
      - cmd: myownpki-agent-setup
{% set _ = restart_on.append('myownpki-agent-deployment-absent-' ~ a) %}
{% endfor %}

{% for d in m['deployments'] %}
myownpki-agent-deployment-{{ d['name'] }}:
  cmd.run:
    - name: {{ d['command'] | yaml_dquote }}
    - unless: {{ list_guard | replace('@NAME@', d['name'] | quote) | yaml_dquote }}
    - require:
      - cmd: myownpki-agent-setup
{% set _ = restart_on.append('myownpki-agent-deployment-' ~ d['name']) %}
{% endfor %}

{% if restart_on %}
# try-restart restarts a running agent and never starts a stopped one, so a host that
# waits for approval stays down.
myownpki-agent-restart:
  cmd.run:
    - name: systemctl try-restart myownpki-agent
    - onchanges:
{% for sid in restart_on %}
      - {{ 'file' if sid == 'myownpki-agent-config' else 'cmd' }}: {{ sid }}
{% endfor %}
    - require:
      - cmd: myownpki-agent-setup
{% if m['config_source'] != '' %}
      - cmd: myownpki-agent-sandbox
{% endif %}
{% endif %}

{% endif %}
