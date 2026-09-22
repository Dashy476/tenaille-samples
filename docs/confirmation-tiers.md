# Confirmation tiers

Every finding carries a ceiling. The brief is not allowed to talk past it.

| Ceiling | Meaning in Tenaille | This sample |
| --- | --- | --- |
| `version_match` | The recorded upstream version sits in a published CPE / version range. | Used. |
| `active_verify` | The service is reachable and the banner or recorded config agrees. | Named only. Not run. |
| `template_verified` | A non-destructive check template agrees with the response. | Named only. Not run. |

Sample output sets the ceiling to `version_match` for every finding, including when the inventory also records `AllowAgentForwarding`. Recording a config field is not an active verification of the running daemon.

## What version match is not

- Not proof the distro package is unpatched. Ubuntu and others backport fixes and keep the upstream number.
- Not proof the service is exposed.
- Not proof the issue is reachable on this build.
- Not compromise. The word "exploited" is rejected by `validate_brief` when the ceiling is `version_match`.

`tests/test_confirmation.py` builds a brief that says the host was exploited and asserts that validation fails. The generated CVINFERNO and CVBASTION text must pass the same check.

## Priority is not CVSS

`context_priority` uses KEV, EPSS, exposure, and the ceiling.

- A lab-only fixture is never P1, no matter the CVSS base score.
- A KEV flag on a lab fixture is P2: catalog weight, still not an incident.
- No KEV and no EPSS on a lab fixture is P3: hygiene.
- P1 requires an internet-facing exposure plus catalog weight. The fixtures in this tree are not internet-facing.

EPSS is null in the shipped fixtures, so it never boosts them.
