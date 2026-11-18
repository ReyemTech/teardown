# Security policy

## Supported releases

Security fixes target the latest published `tech-teardown` release. Older
versions may not receive backports. Check the [changelog](CHANGELOG.md) and
[PyPI](https://pypi.org/project/tech-teardown/) for the current version.

## Report a vulnerability privately

Use [GitHub's private vulnerability reporting](https://github.com/ReyemTech/teardown/security/advisories/new)
for a vulnerability in Teardown itself. Include the affected version, impact,
minimal reproduction, and a proposed fix if you have one. If private reporting
is unavailable, email `mario@reyem.tech` with subject `teardown security`.
Please do not open a public issue before coordinated disclosure.

Reports about a **site being scanned** belong to that site's operator or its
published disclosure channel. A Teardown finding is evidence for review, not
proof of exploitability. Do not send us third-party credentials, raw source
maps, or personal data from a target. Redact reproduction material and use a
synthetic fixture whenever possible.

We will acknowledge a usable report, investigate its impact, and coordinate a
fix and disclosure with the reporter. We cannot promise a fixed response or
release deadline. Please avoid destructive testing, privacy violations, and
access beyond what is needed to demonstrate the issue.
