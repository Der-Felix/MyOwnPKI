---
title: Install the agent and add a host
summary: Use the Add host assistant to put the agent on a Linux host, admit it and follow it until its first certificate is deployed.
audience: Admins who manage certificates for Linux hosts
order: 40
site: /hosts/
sources:
  - docs/OPERATIONS.md
  - internal/web/app_hostadd.go
  - internal/web/hostadd.go
  - internal/web/app_agents.go
  - cmd/myownpki-agent/main.go
  - internal/agent/deployment_cli.go
---

## What the agent does

A certbot-style client only fetches a certificate. The agent, `myownpki-agent`, also puts it where the service reads it,
tests the service, reloads it and undoes the change if anything fails. It asks for its certificates over ACME like any
client, writes only below the directories its own configuration allows, and runs only the hooks that configuration names.
The server never sends it a command; it only tells the server what it deployed and how it is.

## What the server needs first

The **Add host** entry in the menu appears only while agents are on and your role can read them. Behind it the server needs:

- an agent CA: an intermediate directly below the root whose EKU limit is `clientAuth` only. It signs the agents' short
  client certificates (see [Build a certificate authority](/guides/build-a-ca));
- the `agent` section of the server configuration, with its listener port reachable from the hosts;
- ACME and a [domain](/domains) that covers the name of every host, because the agent proves its name with http-01.

## Add the host

Open [Add host](/hosts/add). The assistant has four steps and stores nothing for itself.

1. **Your answers.** The exact host name (a fully qualified name that a domain covers), the service (an entry marked
   *example recipe* is written from the service's documentation and not yet tried on a live host, so use a test host
   first), the http-01 challenge (*webroot* when a web server already answers port 80, *standalone* when the agent may
   open port 80 itself), and the package to install.
2. **Admission.** The page shows the ways to get the host admitted and the approval each one still needs. A **single-use
   join token** is made for this host and works once for 15 minutes; it needs an admin and a fresh second factor. An
   existing **enrollment pass** is offered when one covers the host. With **no secret** the host waits in
   [Enrollment requests](/agents/enrollments) for one approval.
3. **Commands, shown once.** Run the blocks as root on the *target host*, not on the PKI server. They write the token
   file (never on a command line), download the root and the package and check them against the values the page shows
   from your signed-in session, install, run `setup` and add the deployment. The page does not keep a token, so start
   the assistant again if you lose it.
4. **Progress.** The page reloads itself and shows *Host enrolled*, *Agent online* and one row per deployment.
   A host that waits for approval shows **Approve** and **Refuse** buttons to an admin.

If `setup` ends with *Enrollment is pending*, the service stays disabled. After the approval run
`systemctl enable --now myownpki-agent` on the host.

## Look before you change

On a host that already has an agent, `deployment add` can show what a recipe would write. `--dry-run` prints a diff of
the agent configuration and the systemd drop-ins and writes nothing:

```bash
sudo /usr/local/bin/myownpki-agent deployment add nginx --recipe nginx --name www.homelab.lan --webroot /var/www/acme --acme-directory {acme_directory} --create-dirs --dry-run
```

## Check it worked

On the host, `status` shows the enrollment, the agent certificate and the state of every deployment:

```bash
sudo /usr/local/bin/myownpki-agent status
```

```bash
sudo /usr/local/bin/myownpki-agent deployment list
```

```bash
sudo systemctl status myownpki-agent
```

In the UI the [Agents](/agents) page shows when the host last reported, the serial and expiry of each certificate and the
last error. A deployment is *deployed* once the service serves the new certificate. If the test hook or the reload
fails, the agent puts the old files back and reports *rolled back* with the reason.

## When it fails

- **The commands do not run as expected:** run them as root, on the target host.
- **Enrollment waits:** approve it under [Enrollment requests](/agents/enrollments) and enable the service.
- **http-01 fails:** the server must reach port 80 of the host under its name, and with webroot the directory must exist.
- **A name is refused:** a domain must cover it, and the agent may order only the names its enrollment allowed.

The longer page lists the `setup` options, the enrollment passes for roll-outs, the systemd sandbox and ports below 1024.
