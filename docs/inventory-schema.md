# Inventory schema

HARBNGR writes one JSON document per host. This sample ships the documents already written. The schema is version `1.0`.

A file must include:

| Field | Meaning |
| --- | --- |
| `schema_version` | `"1.0"` |
| `fixture` | `true` in this sample. Anything else is refused. |
| `authorization` | `"synthetic-lab"` in this sample. Anything else is refused. |
| `collected_by` | Which collector produced the file. The sample uses `HARBNGR-sample`. |
| `host.id` | Stable name, for example `lab-web-01`. |
| `host.hostname` | Display name. |
| `host.exposure` | `lab-only` or, in a later authorized deployment, `internet-facing`. Priority uses this. |
| `host.addresses` | List of addresses. Fixtures use TEST-NET-3 (`203.0.113.0/24`) only. |
| `host.os.family` | `linux`, `windows`, or `macos`. |
| `host.os.distro` | Distro or Windows edition name. |
| `host.os.version` | OS version string. |
| `package_managers` | Names already detected, such as `apt` or `winget`. |
| `packages[]` | `{name, version, source}`. Source is where the version was read (`apt`, `uninstall-registry`). |
| `services[]` | `{name, listen, version, config}`. `listen` is a list of recorded endpoints, not a scan result. |
| `identity.sudo_group_members` | List of account names. Empty is allowed. Windows fixtures may leave it empty. |

`services[].config` for `sshd` may include `permit_root_login`, `password_authentication`, and `allow_agent_forwarding`. Values are the recorded strings (`yes` / `no`). Checks do not modify them.

Examples: `examples/lab-web-01.json`, `examples/lab-win-01.json`.

The version string on a package may be a distro revision (`1:8.9p1-3ubuntu0.1`). Confirmation extracts the upstream `8.9p1` token and says so. It does not pretend the revision was checked against an advisory.
