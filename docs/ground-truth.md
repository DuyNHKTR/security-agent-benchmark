# Ground-Truth Detection Mode

This mode measures **capability** — the share of real vulnerabilities a model finds
and how precisely it locates them — instead of the review-scored *quality per dollar*
of the human-adjudicated pipeline. It exists to answer "which model is better at
finding exploitable bugs," which is the axis the quality pipeline deliberately leaves
out (it has no recall).

## The core idea: you never label vulnerabilities

You do **not** need security expertise to build ground truth. A commit that fixed a
security bug already *is* the ground truth:

- You provide `fix_commit` — the commit that patched the vulnerability.
- The harness scans `fix_commit~1`, the last commit that still contained the bug.
- The lines the fix changed are, by definition, where the vulnerability lived. The
  harness reads them straight from `git diff fix_commit~1 fix_commit`.

So finding a case is just finding a "fixes XSS / SQL injection / CVE-…" commit — which
maintainers label, and which CVE databases link to. No manual vulnerability analysis.

### What counts as ground truth

The derivation keeps only source-code hunks. Diff lines in tests, docs, examples,
fixtures, vendored code, and lockfiles are dropped, because a security fix routinely
touches those alongside the real change and counting them would create false answers.
A fix whose diff is *entirely* tests/docs is rejected — pick one that changes
application code.

**Known limitation (be honest about it):** the answer key is "lines the fix touched."
If a fix is incomplete, or the same bug also exists elsewhere the fix didn't touch,
those extra locations are not in the ground truth — a model could find a real variant
and be scored as off-target. This measures *detection of the patched instance*, not
completeness of the class. Prefer fixes that are tightly scoped to the vulnerability.

## Architecture

```
Suite (fix_commit cases)
        │  git rev-parse fix_commit~1        → scan commit (pinned, immutable)
        ▼
Fixture cache ── git diff fix~1 fix ──► truth.json   (file + line regions)
        │
        ▼
Pinned workspace ──► model scan (Claude Code / Codex) ──► report.json
        │
        ▼
Scorer: does any finding location overlap a truth region (±tolerance lines)?
        │
        ▼
detection.json / detection.csv / detection.html  (recall, matrix, precision proxy)
```

Everything upstream of the scorer reuses the existing harness — SHA-pinned fixtures,
disposable workspaces, the shared prompt and report schema, Docker isolation for Codex.
The only additions are truth derivation (`src/lib/truth.ts`) and scoring
(`src/lib/score.ts`). The human-review pipeline is untouched and still available.

## Usage

```powershell
# 1. Copy the template and fill in repositories + security-fix SHAs.
Copy-Item configs/suites/example-known-fix.yaml configs/suites/detection.yaml

# 2. (Optional) Inspect the derived ground truth before running any model.
npm run bench -- truth build --suite configs/suites/detection.yaml
#   xss-fix: scan 4f2a… · 2 region(s), 5 line(s) across 1 file(s)

# 3. Run each model against each case (same commands as the main flow).
npm run bench -- run codex xss-fix --profile codex-gpt-5-5 --suite configs/suites/detection.yaml
npm run bench -- run claude prepare xss-fix --profile claude-fable --suite configs/suites/detection.yaml
#   …follow the generated Claude Code launch command, then:
npm run bench -- run validate <claude-run-directory> --suite configs/suites/detection.yaml

# 4. Score everything and build the visual report.
npm run bench -- score report --suite configs/suites/detection.yaml
#   Detection report: runs/cve-detection-v1/reports
```

`score report` re-derives truth if needed, scores the latest complete run per
(model, case), writes a `score.json` beside each run, and emits `detection.{json,csv,html}`
under `runs/<suite>/reports/`. Use `--tolerance N` to change the line-overlap window
(default ±5).

## What to expect

- **Refusals and failures are visible, not silent.** A model that refused or never
  produced a valid report shows as **"no run"** in the matrix — for Fable this is where
  its cyber safety classifier surfaces. That is a data point, not a gap to hide.
- **A few cases is enough to compare, but not to conclude.** Recall over 2–3 cases is
  noisy; aim for 8–15 fix cases across a range of difficulty before reading much into
  the ranking.
- **This scores detection of the patched bug**, not exploitation and not class coverage.

## Reading the report (`detection.html`)

Open `runs/<suite>/reports/detection.html`. Three sections:

1. **Recall bars** — the headline: share of known vulnerabilities each model located.
   `80% (4/5)` means it found 4 of the 5 seeded bugs.
2. **Detection matrix** — one row per vulnerability, one column per model. Cell colors:
   - **exact** (green) — a finding landed on the fixed line(s).
   - **fuzzy** (yellow) — within ±tolerance lines; right area, imprecise.
   - **miss** (red) — the model reported findings but none on this bug.
   - **no run** (grey) — refused, incomplete, or absent.
   This is where you see *which kinds* of bugs a model misses — scan a red row to spot a
   vulnerability class every model struggles with, or a red column for a weak model.
3. **Summary table** — per model: recall, exact/fuzzy/no-run counts, and
   *on-target findings* (share of all reported findings that hit a known bug). Treat
   on-target as a **directional** precision signal, not a false-positive rate: an
   "off-target" finding may be a real bug outside the seeded set, so it is not
   necessarily wrong.

Stratify by difficulty (the matrix's `Diff.` column): the capability gap between
frontier models shows up almost entirely on the hard cases; everyone finds the easy ones.
