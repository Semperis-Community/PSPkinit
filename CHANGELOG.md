# Changelog

All notable changes to this project will be documented in this file.

## Pull Request History

Deduplicated historical PR records, newest first, with key details retained.

### PR #9 - Temporarily disable code signing

- Source PR: #9
- Base branch: dev
- Head branch: fix/disable-code-signing
- Details:
  - Disable code signing in the active release configuration while centralized Azure federated login is addressed.
  - Setting `enabled: false` causes the release workflow signing gate to skip Azure OIDC login, Key Vault certificate retrieval, and signing steps. Release packaging and publishing remain unaffected.
  - Related tracking: [pipeline-build issue #255](https://github.com/Semperis-Community/pipeline-build/issues/255).
  - Parsed `pipeline-config/ref/signing.yaml` and confirmed `enabled` is Boolean `false`.
  - `git diff --check` passed.

### PR #7 - Upgrade reusable pipeline to v1.3.0

- Source PR: #7
- Base branch: dev
- Head branch: pipeline-upgrade
- Details:
  - Upgrade the reusable pipeline to v1.3.0 for improved release automation and updated pipeline configuration.
  - Refresh shared PowerShell tooling and release/signing scripts, including their integrity hashes.
  - Replace the changelog workflow with the updated release workflow and release configuration.
  - Update reference and sample pipeline configuration for current native build and packaging behavior.
  - No PSPkinit module source changes are included.

### PR #5 - docs(help): fix nine function help validation failures

- Source PR: #5
- Base branch: dev
- Head branch: docs/missing-comment-help
- Details:
  - ```diff
  - Missing or malformed help in nine functions
  - + Valid help with parameters, examples, and output types
  - ```
  - No executable code changed. The function-per-file refactor stays separate.
  - **Before:** Help validation reported nine failures.
  - **After:** Help validation, formatting, and static analysis pass. All 81 tests pass with Pester 5.7.1.
  - **Door:** two-way
  - **Blast Radius:** documentation
