# SigmaHQ rules shipped with Phoenix DFIR

The rules in `rules/` are an unmodified subset of the SigmaHQ rule set (25
Windows, 12 AWS CloudTrail, 10 Linux auditd, 14 Entra ID, 6 GCP and 3
Microsoft 365 rules):

- Source: https://github.com/SigmaHQ/sigma
- Release: `r2026-07-01` (commit `552f3fee420ef232a8e5790c4fae591847e32347`)
- License: Detection Rule License (DRL) 1.1, full text in
  `LICENSE.Detection.Rules.md` and at https://github.com/SigmaHQ/Detection-Rule-License

Each rule file keeps its `author`, `references` and `id` fields. Every alert
Phoenix raises from one of these rules carries the rule author (`rule_author`)
and a link to the rule (`rule_url`), as the DRL 1.1 requires.

The full rule set of the same release can be installed with
`phoenix rules sync`. Other rule archives can be added with
`phoenix rules import <archive.zip>`.
