// Package recipe holds the ready-made deployments behind
// "myownpki-agent deployment add --recipe NAME" (docs/PHASE3.md §11.2): file
// paths, owners, modes, hooks, the local TLS check and the directories the
// hooks need in the systemd sandbox.
//
// It is data only and imports nothing from this module, so the server can
// show the same values (the Add host assistant) without linking the agent.
//
// nginx is known from the agent end-to-end job. The other recipes are
// examples, written from the documentation of each service and not yet run
// on a live host: Example is true for them and Notes says what to verify.
package recipe

import (
	"slices"
	"sort"
)

// Hook is a named command line: an argument vector, never a shell string.
type Hook struct {
	Name    string
	Command []string
}

// Recipe is one service.
type Recipe struct {
	Name    string
	Summary string

	// Profile is "nginx" (Dir) or "file" (Certificate, Chain, Fullchain, Key,
	// or Combined alone).
	Profile string
	// Dir, and every file path of the file profile, may contain {name}: the
	// name of the deployment (a validated name of letters, digits and "-").
	Dir         string
	Certificate string
	Chain       string
	Fullchain   string
	Key         string
	// Combined is the single-file form (HAProxy): the certificate chain and the
	// private key in one PEM file. It excludes the four fields above.
	Combined string

	Owner   string
	Group   string
	KeyMode string

	Hooks      []Hook
	TestHook   string
	ReloadHook string
	// Check is the local TLS check (implicit TLS only); "" means none.
	Check string

	// SandboxWrite lists directories the hooks write; LowPorts lets them bind
	// ports below 1024.
	SandboxWrite []string
	LowPorts     bool

	// Example marks a recipe that was not yet run on a live host; Notes lists
	// what to verify there.
	Example bool
	Notes   []string
}

var recipes = []Recipe{
	{
		Name:    "nginx",
		Summary: "nginx: fullchain.pem and privkey.pem in a directory of their own",
		Profile: "nginx",
		Dir:     "/etc/ssl/myownpki/{name}",
		Owner:   "root",
		KeyMode: "0600",
		Hooks: []Hook{
			{Name: "nginx-test", Command: []string{"/usr/sbin/nginx", "-t"}},
			{Name: "nginx-reload", Command: []string{"/usr/bin/systemctl", "reload", "nginx"}},
		},
		TestHook:     "nginx-test",
		ReloadHook:   "nginx-reload",
		Check:        "127.0.0.1:443",
		SandboxWrite: []string{"/var/log/nginx"},
		LowPorts:     true,
	},
	{
		Name:    "apache2",
		Summary: "Apache on Debian and Ubuntu: fullchain.pem and privkey.pem in a directory of their own",
		Profile: "nginx",
		Dir:     "/etc/ssl/myownpki/{name}",
		Owner:   "root",
		KeyMode: "0600",
		Hooks: []Hook{
			{Name: "apache2-test", Command: []string{"/usr/sbin/apache2ctl", "configtest"}},
			{Name: "apache2-reload", Command: []string{"/usr/bin/systemctl", "reload", "apache2"}},
		},
		TestHook:     "apache2-test",
		ReloadHook:   "apache2-reload",
		Check:        "127.0.0.1:443",
		SandboxWrite: []string{"/var/log/apache2"},
		Example:      true,
		Notes: []string{
			"vhost: SSLCertificateFile /etc/ssl/myownpki/<name>/fullchain.pem and SSLCertificateKeyFile /etc/ssl/myownpki/<name>/privkey.pem (the chain belongs in the first file since Apache 2.4.8); enable mod_ssl with a2enmod ssl",
			"the recipe never edits the Apache configuration; the vhost lines are yours",
			"apache2ctl configtest checks that the files exist and the directives parse; it is not known to check that key and certificate match (the agent checks the pair itself before it writes), so verify what a corrupted file does on a test host",
			"all deployments of this recipe share one test hook and one reload hook, so they are one reload and one rollback group",
			"the local check connects to 127.0.0.1:443 with the certificate's first name as SNI; when Apache listens elsewhere, set --check HOST:PORT (or delete the check line in agent.yaml)",
			"a group such as ssl-cert is needed only when something other than the root-run Apache master reads the key",
		},
	},
	{
		Name:    "httpd",
		Summary: "Apache httpd on the Red Hat family: fullchain.pem and privkey.pem in a directory of their own",
		Profile: "nginx",
		Dir:     "/etc/ssl/myownpki/{name}",
		Owner:   "root",
		KeyMode: "0600",
		Hooks: []Hook{
			{Name: "httpd-test", Command: []string{"/usr/sbin/httpd", "-t"}},
			{Name: "httpd-reload", Command: []string{"/usr/bin/systemctl", "reload", "httpd"}},
		},
		TestHook:     "httpd-test",
		ReloadHook:   "httpd-reload",
		Check:        "127.0.0.1:443",
		SandboxWrite: []string{"/var/log/httpd"},
		Example:      true,
		Notes: []string{
			"vhost: SSLCertificateFile /etc/ssl/myownpki/<name>/fullchain.pem and SSLCertificateKeyFile /etc/ssl/myownpki/<name>/privkey.pem (the chain belongs in the first file since Apache 2.4.8); install mod_ssl (dnf install mod_ssl)",
			"the recipe never edits the httpd configuration; the vhost lines are yours",
			"httpd -t checks that the files exist and the directives parse; it is not known to check that key and certificate match (the agent checks the pair itself before it writes), so verify what a corrupted file does on a test host",
			"SELinux: look at the label of /etc/ssl/myownpki (ls -Z) and run restorecon -R /etc/ssl/myownpki if httpd cannot read the files",
			"all deployments of this recipe share one test hook and one reload hook, so they are one reload and one rollback group",
			"the local check connects to 127.0.0.1:443 with the certificate's first name as SNI; when httpd listens elsewhere, set --check HOST:PORT (or delete the check line in agent.yaml)",
			"a group such as ssl-cert is needed only when something other than the root-run httpd master reads the key",
		},
	},
	{
		Name:     "haproxy",
		Summary:  "HAProxy: one PEM per certificate with the chain and the key in it",
		Profile:  "file",
		Combined: "/etc/ssl/myownpki/haproxy/{name}.pem",
		Owner:    "root",
		Group:    "root",
		KeyMode:  "0600",
		Hooks: []Hook{
			{Name: "haproxy-test", Command: []string{"/usr/sbin/haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"}},
			{Name: "haproxy-reload", Command: []string{"/usr/bin/systemctl", "reload", "haproxy"}},
		},
		TestHook:   "haproxy-test",
		ReloadHook: "haproxy-reload",
		Check:      "127.0.0.1:443",
		Example:    true,
		Notes: []string{
			"haproxy.cfg: bind :443 ssl crt /etc/ssl/myownpki/haproxy/<name>.pem for one certificate, or crt /etc/ssl/myownpki/haproxy/ for every file in the directory; a crt-list is your own file",
			"each deployment writes one file per deployment name (the certificate chain, then the private key, mode 0600); the recipe never edits haproxy.cfg",
			"the test hook checks /etc/haproxy/haproxy.cfg only; when the service uses more (-f /etc/haproxy/conf.d) give the test hook your own command line with --hook and --test-hook",
			"verify that haproxy -c refuses a broken file and that the directory form of crt ignores the agent's temporary .myownpki-* file while it is written",
			"the local check connects to 127.0.0.1:443 with the certificate's first name as SNI; with accept-proxy or a bind to another address set --check HOST:PORT (or delete the check line in agent.yaml)",
			"a check hook binds no port and the sandbox gets no write directory and no low-ports entry; if the agent log shows \"Read-only file system\" or \"Permission denied\" from a hook, add --sandbox-write or --low-ports",
		},
	},
	{
		Name:       "postfix",
		Summary:    "Postfix: one chain file and one key, smtpd_tls_chain_files",
		Profile:    "file",
		Fullchain:  "/etc/ssl/myownpki/postfix/fullchain.pem",
		Key:        "/etc/ssl/myownpki/postfix/privkey.pem",
		Owner:      "root",
		Group:      "root",
		KeyMode:    "0600",
		Hooks:      []Hook{{Name: "postfix-test", Command: []string{"/usr/sbin/postfix", "check"}}, {Name: "postfix-reload", Command: []string{"/usr/bin/systemctl", "reload", "postfix"}}},
		TestHook:   "postfix-test",
		ReloadHook: "postfix-reload",
		Example:    true,
		Notes: []string{
			"main.cf (Postfix 3.4 and later): smtpd_tls_chain_files = /etc/ssl/myownpki/postfix/privkey.pem, /etc/ssl/myownpki/postfix/fullchain.pem (older: smtpd_tls_cert_file and smtpd_tls_key_file)",
			"no local check by default: the agent checks implicit TLS only; add --check 127.0.0.1:465 when master.cf has a submissions listener",
			"verify that \"postfix check\" runs inside the sandbox without writing, and that no group is needed (the key is read before Postfix drops privileges)",
		},
	},
	{
		Name:       "dovecot",
		Summary:    "Dovecot: one chain file and one key",
		Profile:    "file",
		Fullchain:  "/etc/ssl/myownpki/dovecot/fullchain.pem",
		Key:        "/etc/ssl/myownpki/dovecot/privkey.pem",
		Owner:      "root",
		Group:      "root",
		KeyMode:    "0600",
		Hooks:      []Hook{{Name: "dovecot-test", Command: []string{"/usr/bin/doveconf", "-n"}}, {Name: "dovecot-reload", Command: []string{"/usr/bin/systemctl", "reload", "dovecot"}}},
		TestHook:   "dovecot-test",
		ReloadHook: "dovecot-reload",
		Check:      "127.0.0.1:993",
		Example:    true,
		Notes: []string{
			"dovecot.conf 2.3: ssl_cert = </etc/ssl/myownpki/dovecot/fullchain.pem and ssl_key = </etc/ssl/myownpki/dovecot/privkey.pem; 2.4: ssl_server_cert_file and ssl_server_key_file (no <)",
			"verify that a reload makes new connections use the new certificate, and which doveconf option is a syntax-only test on your version",
		},
	},
	{
		Name:      "proxmox",
		Summary:   "Proxmox VE: the files stay outside /etc/pve, pvenode installs them",
		Profile:   "file",
		Fullchain: "/etc/ssl/myownpki/pve/fullchain.pem",
		Key:       "/etc/ssl/myownpki/pve/privkey.pem",
		Owner:     "root",
		Group:     "root",
		KeyMode:   "0600",
		Hooks: []Hook{{Name: "proxmox-install", Command: []string{"/usr/bin/pvenode", "cert", "set", "/etc/ssl/myownpki/pve/fullchain.pem",
			"/etc/ssl/myownpki/pve/privkey.pem", "--force", "1", "--restart", "1"}}},
		ReloadHook:   "proxmox-install",
		Check:        "127.0.0.1:8006",
		SandboxWrite: []string{"/etc/pve"},
		Example:      true,
		Notes: []string{
			"the agent does not write into /etc/pve (a FUSE file system that takes neither chown nor chmod); pvenode validates, installs and restarts pveproxy, and a rollback runs it again on the restored files",
			"verify the pvenode syntax of your version and that pvenode works under the sandbox; run one agent per node",
		},
	},
}

// Names are the known recipes, sorted.
func Names() []string {
	out := make([]string, 0, len(recipes))
	for _, r := range recipes {
		out = append(out, r.Name)
	}
	sort.Strings(out)
	return out
}

// Get returns a copy of the recipe called name.
func Get(name string) (Recipe, bool) {
	for _, r := range recipes {
		if r.Name == name {
			return r.clone(), true
		}
	}
	return Recipe{}, false
}

func (r Recipe) clone() Recipe {
	hooks := make([]Hook, len(r.Hooks))
	for i, h := range r.Hooks {
		hooks[i] = Hook{Name: h.Name, Command: slices.Clone(h.Command)}
	}
	r.Hooks = hooks
	r.SandboxWrite = slices.Clone(r.SandboxWrite)
	r.Notes = slices.Clone(r.Notes)
	return r
}
