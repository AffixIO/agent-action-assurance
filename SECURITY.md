# Security

This research prototype has not undergone an independent security audit. Do not use it as the sole control for production payments, safety-critical systems or agent access.

Privately report suspected vulnerabilities to **kris@affix-io.com**, including affected commit, synthetic reproduction, expected behaviour and impact. Do not send production credentials, private keys or personal data. Please allow assessment before publishing exploit details. No bounty or response-time SLA is promised.

Read [the threat model](docs/THREAT-MODEL.md). Cases allowing blocked dispatch, broader delegation, reused approval or exceeded ancestor budgets are particularly useful.

Only the current development version is maintained. Schema and state changes may require explicit migration; never silently reinterpret historical evidence.
