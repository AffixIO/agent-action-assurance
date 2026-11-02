# Validation record

Local validation performed 2 November 2026 for the 0.2.0 implementation. This is a reproducible engineering check, not independent certification.

| Check | Observed result |
|---|---|
| Python suite, isolated environment, Python 3.13 | 72 passed |
| Published AffixIO 2.0.4 SDK suite | 6 passed |
| Ruff lint and formatting | Passed |
| Source archive and Python wheel builds | Passed |
| Fresh environment installed from unpacked source archive | 72 tests passed; installed command ran from outside source tree |
| Fresh SDK dependency install using frozen lockfile, scripts disabled | Passed; 6 tests passed |
| Python export piped to actual SDK | Artifact integrity and pinned ML-DSA signature valid |
| pnpm production dependency audit | No known vulnerabilities reported at check time |

The demo produced three fictional tool calls. Review, over-budget, changed approval, replay and revoked-parent cases did not call the tool. Concurrency tests include both separate connections in threads and independently spawned processes sharing SQLite.

The clean Python environment resolved cryptography 46.0.7 and pytest 9.2.0. The SDK integration is pinned to affixio 2.0.4 with pnpm 11.25.0. Its package manager requires Node 22.13 or later, which is stated in the instructions.

Two issues found during implementation were corrected: the SDK key pair returns snake-case fields while its signing options use camel case; and the source archive initially omitted test fixtures and supporting guides. The field mapping and explicit package manifest are now tested by the clean-install workflow.

GitHub independently runs Python 3.10, 3.12 and 3.13, wheel installation outside the checkout, and the Node SDK integration. Consult the [specific workflow results](https://github.com/AffixIO/agent-action-assurance/actions/workflows/test.yml) for current status rather than assuming this record covers future changes.

No live models, hosted AffixIO proof generation, external tools, payments, authentication services or remote checkout systems were exercised. Signatures are genuine; business actions and time in the demo are synthetic. No API keys or payment credentials were needed.
