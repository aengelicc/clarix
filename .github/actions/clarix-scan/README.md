# Clarix Scan Action

Composite GitHub Action that runs [Clarix](https://github.com/aengelicc/clarix) static
analysis on a repository and uploads the findings to **GitHub Code Scanning** as
SARIF 2.1.0.

## Usage

```yaml
on: [push, pull_request]

jobs:
  clarix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aengelicc/clarix-scan@v1
        with:
          path: .                     # path to scan
          severity-threshold: low     # show all severities
          fail-on: high               # exit non-zero on high+ (gates the job)
          # clarix-ref: main          # pin to a specific ref of aengelicc/clarix
          # comment-on-pr: true       # post a sticky PR comment
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `path` | no | `.` | Path (relative to repo root) to scan. |
| `severity-threshold` | no | `low` | Minimum severity to include in SARIF. |
| `fail-on` | no | _(same as severity-threshold)_ | Severity at which the action exits non-zero. |
| `clarix-ref` | no | `main` | Git ref of `aengelicc/clarix` to install the CLI from (when `install-from: remote`). |
| `install-from` | no | `remote` | `remote` clones `aengelicc/clarix`; `local` installs from `./backend` in the current checkout (useful for development). |
| `sarif-category` | no | `clarix` | Category label shown in GitHub Code Scanning. |
| `comment-on-pr` | no | `true` | Post/update a sticky PR comment summarising the run. |
| `max-files` | no | _(server default)_ | Override the `MAX_FILES` server setting. |
| `python-version` | no | `3.11` | Python version used to run the CLI. |

## Outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Absolute path to the generated SARIF file on the runner. |
| `finding-count` | Number of findings in the SARIF report. |
| `exit-code` | CLI exit code (0 = clean, 1 = findings ≥ fail-on). |

## Exit codes

The action surfaces Clarix's exit code on the `exit-code` output but does not
fail the job by itself — control gating via `fail-on` should be done in the
caller workflow if needed. Example:

```yaml
- uses: aengelicc/clarix-scan@v1
  id: clarix
  with: { fail-on: high }
- run: echo "Clarix found ${{ steps.clarix.outputs.finding-count }} issue(s)"
```

## Notes

- Clarix is static-only in CLI mode — no LLM key required, no API costs, no
  external calls. Scans a typical repo in seconds.
- The action uploads SARIF on every run (even when there are zero findings) so
  that GitHub Code Scanning shows a clean status badge.
- Findings appear in the **Security → Code scanning** tab under the category
  name set by `sarif-category`.
