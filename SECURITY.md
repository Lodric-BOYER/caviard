# Security policy

Caviard exists to keep personal data and secrets out of traces and logs, so a way around
it is a vulnerability, even when nothing crashes.

## Supported versions

Caviard is in alpha (0.x): only the latest release receives security fixes.

## Reporting a vulnerability

Please do not open a public issue. Report it privately through GitHub: open the
[Security tab](https://github.com/Lodric-BOYER/caviard/security) of the repository and
choose **Report a vulnerability**.

Include a minimal reproduction **with synthetic data only**: never send real personal
data, real keys or real traces. Generated identifiers with valid check digits are fine.

You will get an acknowledgement within 7 days and an assessment within 14 days. Fixes are
released as soon as they are ready; the advisory is published with the release and credits
you, unless you prefer otherwise. The target for a full disclosure is 90 days.

## What counts

- A personal value or a secret that reaches an exporter, a log or a report although a
  detector or a key rule should have caught it, in particular through an error path.
- An analysed value or the pseudonym key that appears in an error message, a log, a
  warning or an audit report.
- An input that makes redaction slow (regular expression denial of service) or crash.
- A weakness in pseudonymisation, such as tokens that can be linked without the key.
- An issue in the build or release process that could let someone publish a modified
  package.

Detection gaps that are documented limitations (names in free text, numbers without
context words) are not vulnerabilities, but reports that show how to close them are
welcome as regular issues, with synthetic data.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the threats Caviard addresses and the ones it
does not.
