# Changelog

All notable changes to this project will be documented in this file.

## Pull Request History

Deduplicated historical PR records, newest first, with key details retained.

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
