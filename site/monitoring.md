---
title: "Monitoring and notifications"
description: "How the MyOwnPKI server watches itself, how to get e-mail or webhook messages, what each alert means and what to do about it."
permalink: /monitoring/
---

Since v0.3.3 the server watches itself. **Every minute** it checks the certificates, the CAs and their
CRLs, the seal state and the agents, and keeps one **alert** per problem. The alerts are on the
*Alerts* page, in the *Needs attention* block of the dashboard and in `GET /api/v1/alerts`. If you set
up **e-mail** or a **webhook**, every change also goes out as a message.

The checks and the messages **work while the server is sealed**. That is the point: the most important
alert is "the server is sealed", and a sealed server cannot decrypt anything. For that reason the
channels live in the configuration file and their secrets in files next to it, not in the database.
Without a channel nothing breaks; the alerts still open and show in the UI, only nobody is told.
Since v0.3.4 the server can also check what a host really serves; that is the
[TLS scan]({{ '/tls-scan/' | relative_url }}). Since v0.3.8 the *Reports* page charts what the alerts
leave out (the expiry of the next 13 weeks, the alert history, the agent fleet) and the *Analysis* page
points out oddities that no alert covers; both are on [Reports and analysis]({{ '/reports/' | relative_url }}).
This page is the condensed version of
[operations guide chapter 13]({{ '/reference/operations/' | relative_url }}#13-monitoring-and-notifications).

* TOC
{:toc}

## Set up e-mail

1. If the mail server needs a login, create the password file. The service user must be able to read
   it, nobody else:

   ```bash
   sudo install -m 0640 -o root -g myownpki /dev/null /etc/myownpki/smtp-password
   ```

   ```bash
   sudo bash -c 'read -rsp "SMTP password: " p && printf "%s" "$p" > /etc/myownpki/smtp-password'
   ```

   The first command creates the empty file with owner and mode, the second fills it without the
   password appearing on the screen, in the shell history or in a process list. The file is read at
   each send.

2. If the mail server's certificate comes from your own CA, give the server your root as an extra
   trusted root. Any readable PEM file works, for example the root from the trust page:

   ```bash
   sudo curl -fsS -o /etc/myownpki/mail-ca.pem http://pki.homelab.lan/ca/root/1.pem
   ```

   (`root` and `1` are the name and generation of your root.) Compare its fingerprint with the admin UI
   before you rely on it.

3. Add the channel to `/etc/myownpki/config.yaml`:

   ```yaml
   notify:
     email:
       smtp: mail.homelab.lan:587           # host:port
       security: starttls                   # starttls | tls | none
       username: pki@homelab.lan            # optional; with it password_file is required
       password_file: /etc/myownpki/smtp-password
       from: pki@homelab.lan
       to: ops@homelab.lan, lead@homelab.lan   # comma-separated, one message for all
       ca_file: /etc/myownpki/mail-ca.pem   # optional, added to the system roots
   ```

4. Check the file **as the service user**. A secret that only root can read passes as root and then
   fails for the server:

   ```bash
   sudo -u myownpki /usr/local/bin/myownpki config check --config /etc/myownpki/config.yaml
   ```

5. Restart the service. The channels are read at start, and **every start is sealed**, so unseal
   it again:

   ```bash
   sudo systemctl restart myownpki
   ```

6. [Send a test message](#test-the-channels).

| `security` | Usual port | What happens |
|---|---|---|
| `starttls` (default) | 587 | Connects in plain text and switches to TLS before the login. Refuses if the server does not offer STARTTLS. |
| `tls` | 465 | TLS from the first byte |
| `none` | 25 | No encryption. Only without `username`: a password never travels in plain text, and `config check` refuses the combination. For an internal relay that accepts mail from the server's address. |

The server's certificate is always checked against the system roots plus `ca_file`, and it must carry the
host name you wrote in `smtp` (an IP address in `smtp` needs that IP in the certificate). The minimum is
TLS 1.2. The login is `PLAIN` and only inside TLS; a server that offers only `LOGIN` or OAuth is not
supported, so use a relay for the server's address. One delivery has 20 seconds, and e-mail does
**not** use the proxy variables: the mail server must be reachable directly.

## Set up a webhook

A webhook is one `POST` with a JSON body to a URL of yours: a small receiver, or a relay that turns it
into Slack, Teams, ntfy or a ticket.

1. Create the secret, the key that signs every call, and give the same value to the receiver:

   ```bash
   sudo install -m 0640 -o root -g myownpki /dev/null /etc/myownpki/webhook-secret
   ```

   ```bash
   openssl rand -hex 32 | sudo tee /etc/myownpki/webhook-secret >/dev/null
   ```

2. Add the channel to `config.yaml`:

   ```yaml
   notify:
     webhook:
       url: https://hooks.homelab.lan/myownpki
       secret_file: /etc/myownpki/webhook-secret   # required
       ca_file: /etc/myownpki/hooks-ca.pem         # optional, added to the system roots
   ```

3. Check, restart, unseal and test, as for e-mail.

The URL must be `https://`; `http://` is accepted only for a loopback address. A 2xx answer is success;
a redirect is **not followed** and counts as a failure. One call has 10 seconds. Every request carries
`X-MyOwnPKI-Signature: sha256=<hex HMAC-SHA256 of the body, key = the text of the secret file>`. Verify
it on the **raw body**, before you parse it, and compare in constant time. The signature proves who
sent the body but not when, so a receiver that must reject replays has to remember what it has seen.
Unlike e-mail, the webhook honors `HTTPS_PROXY` and `NO_PROXY` of the **server process**, read once at
start (with systemd: `systemctl edit myownpki` and `Environment=` lines).

The body looks like this:

```json
{
  "server": "pki.homelab.lan",
  "created": "2026-11-11T12:00:03Z",
  "events": [
    {
      "kind": "sealed",
      "subject": "Server sealed",
      "severity": "warning",
      "state": "opened",
      "since": "2026-11-11T11:50:01Z",
      "detail": "The server has been sealed since 2026-11-11 11:50 UTC – it signs nothing: …",
      "link": "https://pki.homelab.lan:9443/unseal"
    }
  ]
}
```

`state` is `opened`, `raised` (warning to critical), `reminder`, `resolved`, or `test`.

## In the container

Every key is also a variable: `MYOWNPKI_` plus the path in upper case, `.` as `_`. The secret files are
files: mount them **read-only** and make them readable for UID 65532.

```yaml
services:
  myownpki:
    hostname: pki.homelab.lan   # the server name in the message subject
    environment:
      MYOWNPKI_NOTIFY_EMAIL_SMTP: mail.homelab.lan:587
      MYOWNPKI_NOTIFY_EMAIL_SECURITY: starttls
      MYOWNPKI_NOTIFY_EMAIL_USERNAME: pki@homelab.lan
      MYOWNPKI_NOTIFY_EMAIL_PASSWORD_FILE: /run/secrets/smtp-password
      MYOWNPKI_NOTIFY_EMAIL_FROM: pki@homelab.lan
      MYOWNPKI_NOTIFY_EMAIL_TO: ops@homelab.lan, lead@homelab.lan
      MYOWNPKI_NOTIFY_WEBHOOK_URL: https://hooks.homelab.lan/myownpki
      MYOWNPKI_NOTIFY_WEBHOOK_SECRET_FILE: /run/secrets/webhook-secret
    volumes:
      - ./secrets/smtp-password:/run/secrets/smtp-password:ro
      - ./secrets/webhook-secret:/run/secrets/webhook-secret:ro
```

The thresholds are `MYOWNPKI_MONITOR_EXPIRY_DAYS`, `MYOWNPKI_MONITOR_CA_EXPIRY_DAYS`,
`MYOWNPKI_MONITOR_SEALED_AFTER`, `MYOWNPKI_MONITOR_AGENT_SILENT_AFTER` and
`MYOWNPKI_MONITOR_REPEAT_EVERY`. A change needs `docker compose up -d`, and the container restarts
sealed.

## Test the channels

```bash
sudo -u myownpki /usr/local/bin/myownpki notify test --config /etc/myownpki/config.yaml
```

One test message goes through every configured channel, right now, with the server's configuration and
secret files; `--channel email` or `--channel webhook` limits it. It needs neither a running nor an
unsealed server and sends no alerts. A success prints a line per channel:

```text
email    sent to ops@homelab.lan, lead@homelab.lan via mail.homelab.lan:587
webhook  sent to hooks.homelab.lan
```

A failure prints `FAILED: <reason>` and the exit code is 1; the reason names the host and what went
wrong, never a password or the webhook's path. In a container:

```bash
docker compose run --rm myownpki notify test
```

The same test from the running server: *Alerts → Notifications → Send test message* (tenant admins), or
`POST /api/v1/notifications/test` with a tenant admin's API token. These are limited to one every ten
seconds and audited as `notification.test`.

**`config check`** shows what is in effect, and reads the secret and CA files. A missing, unreadable or
empty secret is an error (exit code 1), because every message would fail; with no channel at all it only
warns. It does not connect to anything, so only a test shows that the mail server or receiver accepts the
message.

## The alerts

| Alert | Opens when | Warning | Critical |
|---|---|---|---|
| `cert_expiry` | a valid end-entity certificate ends soon and **no newer valid certificate covers the same names** | 14 days left | 3 days left, or expired |
| `ca_expiry` | the current certificate of an active CA ends soon | 90 days left | 30 days left, or expired |
| `crl` | the newest CRL of a CA generation is not current | half its lifetime has passed without a renewal, or none was ever published | past its next update |
| `sealed` | the server has been sealed longer than `sealed_after` | after 10 minutes | a CRL of an online CA is less than 24 hours from its next update |
| `agent_silent` | an active agent that reported before has not reported | after 1 hour | after 24 hours |
| `agent_certificate` | an active agent's own certificate has less than 48 hours left | – | always |
| `deploy_failed` | the last report of a deployment is `failed` or `rolled_back` | always | – |
| `scan_mismatch`, `scan_expiry`, `scan_unreachable`, `scan_chain` | the TLS scan finds that an endpoint you entered serves the wrong or an expiring certificate, is down, or sends an incomplete chain (v0.3.4) | see [TLS scan]({{ '/tls-scan/' | relative_url }}#the-alerts) | see [TLS scan]({{ '/tls-scan/' | relative_url }}#the-alerts) |

An alert changes its severity while it is open and closes by itself at the next check once the cause is
gone. Details are in the
[operations guide §13.6]({{ '/reference/operations/' | relative_url }}#136-the-alerts). What to do:

| Alert | What it means, and what to do |
|---|---|
| `cert_expiry` | A certificate runs out and nothing replaces it. With ACME the client should have renewed: find out why not ([ACME and http-01]({{ '/troubleshooting/' | relative_url }}#acme-and-http-01)). For an agent look at its page, `journalctl -u myownpki-agent` and *Renew now*. Otherwise issue a new certificate for the same names and deploy it, or revoke the old one if it is not needed. The alert closes when the replacement is **issued**; whether the host serves it is still your check. |
| `ca_expiry` | Everything below the CA stops validating on that day. Renew the CA from its page under *Certificate authorities* well before, and give clients what they need if the renewal brings a new root. |
| `crl` | Clients that check revocation reject certificates below a CA whose CRL has expired. For an online CA the usual cause is a sealed server: unseal it. For a CA with an **offline root** nobody renews the root's CRL automatically: sign a new one on the offline root and upload it on the root's page. |
| `sealed` | The server signs nothing. Unseal it (*Unseal* in the banner, or `serve --unseal`). If you do not know why it sealed, read the audit log first. |
| `agent_silent` | Check `systemctl status myownpki-agent` and `journalctl -u myownpki-agent` on the host. Typical causes: the host or service is down, port 8444 is blocked, the agent's proxy setting, or the server's agent listener certificate expired while sealed. |
| `agent_certificate` | The agent's 7-day certificate was not renewed and ends within 48 hours. Fix the connection while it is still valid, as for `agent_silent`. |
| `deploy_failed` | The previous certificate is still in place but ages. Open the agent's page for the error, then the log on the host. The alert closes with the next successful report. |

## Thresholds

The defaults suit most installations. Set them in `config.yaml` and restart:

```yaml
monitor:
  expiry_days: "14, 3"
  ca_expiry_days: "90, 30"
  sealed_after: 10m
  agent_silent_after: 1h
  repeat_every: 24h
```

| Key | Default | Allowed |
|---|---|---|
| `monitor.expiry_days` | `"14, 3"` | warning and critical days for end-entity certificates; warning 2 to 90, critical at least 1 and below warning |
| `monitor.ca_expiry_days` | `"90, 30"` | the same for CA certificates; warning 2 to 365 |
| `monitor.sealed_after` | `10m` | 1m to 1h |
| `monitor.agent_silent_after` | `1h` | 10m to 24h |
| `monitor.repeat_every` | `24h` | 1h to 168h |

A value outside its range makes the server refuse to start and `config check` fail, naming the key. The
keys of the TLS scan (`monitor.scan_*`) are on the [TLS scan]({{ '/tls-scan/' | relative_url }}#settings) page.

## How messages behave

- **One digest per minute at most.** After each check the server sends what changed as one message per
  channel. A minute without a change sends nothing.
- The e-mail subject counts them: `[MyOwnPKI] pki.homelab.lan: 2 new, 1 resolved`. Each alert lists its
  severity, what it is, what to do and a link to the object in the UI (links need a name in
  `admin.tls_names`).
- **Reminders** every `repeat_every` while an alert stays open; a final message when it is resolved.
- **While no channel is configured nothing is marked as notified.** The first message after you
  configure one lists **every alert that is open then**.
- **Retries:** messages are queued in `system.db` and survive a restart. A failed delivery is retried
  after 1 minute, 5 minutes, 30 minutes and 2 hours; after the fifth failed attempt the message is
  **dropped**.

Set up an alarm in your log system on the log message `notification dropped after the last retry`: it
is the one case where the server tried and nobody was told.

```bash
journalctl -u myownpki -o cat | grep -E 'notification|"alert"'
```

## Reading the Alerts page

*Alerts* lists the open alerts first (critical before warning, oldest first) and then those resolved in
the last 7 days. Each row says what is wrong, what to do, and links to the certificate, CA or agent.
Open alerts also show as the figure *Open alerts* on the dashboard. The page and `GET /api/v1/alerts`
need a tenant-wide role of *viewer* or higher; a role limited to one CA gets 403, because alerts name
certificates, CAs and hosts of the whole tenant. Only a tenant admin can send the test message.
The server keeps resolved alerts for 30 days; the *Reports* page shows how many alerts opened in each of
the last five weeks ([Alerts]({{ '/reports/' | relative_url }}#alerts)).

## Two things to know before you rely on it

- **A restart seals the server.** Changing a channel or a threshold means a restart, and a restart means
  an unseal in the browser. Do it when nobody waits for a certificate.
- **No message is sent while the server is down.** It tells you about its own sealed state, not about being
  off. Watch from outside: `myownpki healthcheck`, or your monitoring on `/healthz` of the admin
  listener. `/healthz` says nothing about the seal state on purpose.

When no message arrives, work from the server outward; the checklist and the table of error messages are
in [operations guide §13.10]({{ '/reference/operations/' | relative_url }}#1310-when-no-message-arrives) and
under [Troubleshooting]({{ '/troubleshooting/' | relative_url }}#notifications).
