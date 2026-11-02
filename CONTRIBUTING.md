# Contributing

Reproducible failure cases and realistic integration boundaries are welcome. Discuss large features in an issue first. Report vulnerabilities privately under SECURITY.md.

Install `.[dev]`, then run `python -m pytest -q`, `ruff check .`, `ruff format --check .` and `python -m build`. SDK changes also require its Node tests and piped Python-to-SDK demo.

Each enforcement change needs a successful and an adversarial case proving blocked handlers do not run. Test restarts/concurrency when changing state. Never weaken checks or hard-code successes to make tests pass.

Use synthetic data. Do not commit keys, credentials, databases, personal data, production payloads, bytecode or dependency directories. No live payments or unsolicited agent activity in tests.

Use supported SDK interfaces and precise verification claims. Do not claim standards certification, production readiness, total prompt-injection prevention or vendor endorsement.
