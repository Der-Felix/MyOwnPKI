# Certificate presets

Each `*.yaml` file in this directory is one built-in certificate profile. The files are embedded
into the `myownpki` binary and validated at startup by `internal/ca/preset` – a broken preset stops
the server with a list of every problem found, instead of producing wrong certificates.

They were ported 1:1 from `legacy/lib/presets.sh`. `TestLegacyParity` compares both on every test
run; change the YAML only together with the legacy script (or deliberately, by adapting the test).

## Fields

| Field | Meaning |
|---|---|
| `name` | Preset name; must equal the file name without `.yaml` |
| `description`, `usage` | Shown in the UI and CLI |
| `family` | Group for deployment guides: `server`, `vpnserver`, `client`, `codesign`, `ocsp`, `timestamp`, `custom` |
| `validity_days` | Default lifetime (1–3650) |
| `key_usage.rsa` | Key usages for RSA keys |
| `key_usage.other` | Key usages for ECDSA and Ed25519 keys – these can only sign, so `keyEncipherment`/`dataEncipherment` are rejected |
| `ext_key_usage.usages` | Extended key usages by name (`serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`, `timeStamping`, `OCSPSigning`, `ipsecIKE`) or as dotted OID |
| `ext_key_usage.critical` | Mark the EKU extension critical (required for `timeStamping`, RFC 3161) |
| `subject_alt_names.required_any_of` | At least one SAN of these types is required (`dns`, `ip`, `email`, `uri`) |
| `subject_alt_names.offered` | SAN types the UI asks for |
| `common_name_from` | Derive the CN from the first `dns` or `email` SAN (`""` = entered freely) |
| `openssl_purpose` | `openssl verify -purpose` that certificates of this preset must pass (`any` = none) |
| `ocsp_no_check` | Add `id-pkix-ocsp-nocheck` (only with `OCSPSigning`) |
| `customizable` | Key usage and EKU may be chosen per certificate (only family `custom`) |
| `wildcard` | Allow (and require) a `*.domain` DNS name and add the base domain as a SAN; every other preset rejects wildcard names |

## Rules the loader enforces

- Unknown fields are errors – a typo can't silently drop a setting.
- No CA key usages (`keyCertSign`, `cRLSign`) – presets describe end-entity certificates only.
- `serverAuth` needs a required `dns` or `ip` SAN; `emailProtection` needs a required `email` SAN.
- `timeStamping` must be the only EKU and critical.
- `anyExtendedKeyUsage` is never allowed; well-known EKUs must be written by name, not by OID.
- `openssl_purpose` must match the EKUs (e.g. `sslserver` needs `serverAuth`).

What the presets do **not** decide: the extensions of a certificate never come from the CSR. The
CA takes only the requested names from a CSR, checks them against policy and name constraints, and
builds every extension from the preset.
