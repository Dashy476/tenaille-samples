# Public starter pack

Twelve non-destructive checks. Each one reads a field in an inventory JSON file. None of them open a socket, edit a config, try a password, or carry an exploit template.

| Check | What it reads |
| --- | --- |
| `ssh-listen-address` | `services[name=sshd].listen` |
| `sshd-version` | `services[name=sshd].version` |
| `agent-forwarding-flag` | `AllowAgentForwarding` as recorded |
| `package-manager-present` | `package_managers` |
| `sudo-group-membership` | `identity.sudo_group_members` is a list |
| `os-release-present` | `host.os.version` |
| `exposure-label` | `host.exposure` |
| `permit-root-login` | `PermitRootLogin` as recorded |
| `password-authentication` | password-auth flag as recorded |
| `openssh-package` | `openssh-server` package version |
| `listening-service-recorded` | at least one service row |
| `authorization-label` | `authorization` is `synthetic-lab` |

A missing field is `not-recorded`, not a vulnerability. HARBNGR runs this pack from `python -m tenaille recon`.

This is the whole public check set. There is no larger corpus in this tree.
