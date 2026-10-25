# MyOwnPKI agent guidance

Read [CLAUDE.md](CLAUDE.md) and load the project skill in
[.claude/skills/myownpki/](.claude/skills/myownpki/) before changing code,
schemas, APIs, certificates, or reviews. Its referenced rules are binding.

New or changed CI steps always go through `scripts/ci` and `task ci:local`.
Run `task ci:local` before every report and include every SKIP line in that report.
Set `MYOWNPKI_CI_DISPOSABLE=1` only on a machine that will be discarded afterwards;
the destructive systemd/install steps replace units, binaries and state as root.
