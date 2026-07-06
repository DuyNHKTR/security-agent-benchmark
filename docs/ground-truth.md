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

### Optional advisory metadata (still no labeling)

Two per-case fields sharpen scoring and cost nothing but a copy-paste from the
advisory that led you to the fix commit:

- `cwe` — the advisory's CWE id(s), e.g. `cwe: CWE-79` or `cwe: [CWE-79, CWE-80]`.
  GHSA and CVE entries list this. When set, a location hit only counts as **detected**
  if an on-target finding reports a matching CWE; right-lines-wrong-reason scores
  **loc-only** instead. Without it, location overlap alone counts as detected.
- `training_cutoff` (per model profile) — the vendor-published training cutoff.
  Cases whose fix commit predates it are marked **†** in the matrix: the model may
  remember the patch rather than find the bug. Prefer fixes committed after every
  profile's cutoff; treat † cells as soft evidence.

## Architecture

```
Suite (fix_commit cases)
        │  git rev-parse fix_commit~1        → scan commit (pinned, immutable)
        ▼
Fixture cache ── git diff fix~1 fix ──► truth.json   (pre- and post-image regions,
        │                                             fix date, expected CWEs)
        ▼
Pinned workspace ──► model scan (Claude Code / Codex) ──► report.json
        │            (--control variant scans fix_commit itself)
        ▼
Scorer: span-capped location overlap (±tolerance) + CWE agreement
        │
        ▼
detection.json / detection.csv / detection.html
  (recall + 95% CI, strict recall, matrix, McNemar pairs, calibration,
   confirmed false positives from control runs)
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
(model, case, variant), writes a `score.json` beside each run, and emits
`detection.{json,csv,html}` under `runs/<suite>/reports/`. Use `--tolerance N` to
change the line-overlap window (default ±5) and `--span-cap N` to change how many
total lines a finding may cite and still earn credit (default 40; 0 disables). The
cap is on the finding's **total** cited lines, so neither one giant range nor many
small ranges tiling the repo can farm overlap credit.

### Negative controls (recommended)

Re-run each case with `--control` appended to the same `run codex` / `run claude
prepare` command. The workspace is built from `fix_commit` itself — the patched
code — so the bug is provably absent. Scoring uses the fix diff's post-image lines:

- A finding on the patched region is a **confirmed false positive** (not a proxy —
  git proves the bug is gone there). Hunks that only *deleted* lines produce no
  control region: no patched line exists at that offset, so nothing there can be
  called a confirmed false positive. A case whose fix is deletion-only therefore
  has no evaluable control site at all — its control runs are excluded from the
  discrimination numbers instead of counting as automatic passes.
- **Discrimination** = flagged the vulnerable commit *and* stayed clean at the
  patched site. A model that flags both is pattern-matching or remembering, not
  analyzing. This doubles as a practical contamination probe. A vague, over-broad
  finding overlapping the patched region voids discrimination even though it is
  too imprecise to count as a confirmed false positive.

Control runs are optional per case; the report only shows the section when at
least one exists. They roughly double run cost — prioritize them for cases where
models score suspiciously well.

## What to expect

- **Refusals and failures are visible, not silent.** A model that refused or never
  produced a valid report shows as **"no run"** in the matrix — for Fable this is where
  its cyber safety classifier surfaces. That is a data point, not a gap to hide.
- **A few cases is enough to compare, but not to conclude.** Recall over 2–3 cases is
  noisy; aim for 8–15 fix cases across a range of difficulty before reading much into
  the ranking.
- **This scores detection of the patched bug**, not exploitation and not class coverage.

## Reading the report (`detection.html`)

Open `runs/<suite>/reports/detection.html`.

1. **Recall bars** — the headline: share of known vulnerabilities each model detected,
   with a **95% Wilson interval** drawn on each bar. Overlapping intervals mean the
   suite is too small to rank those models — add cases instead of reading the order.
2. **Detection matrix** — one row per vulnerability, one column per model. Cells:
   - **exact** (green) — a finding landed on the fixed line(s).
   - **fuzzy** (yellow) — within ±tolerance lines; right area, imprecise.
   - **loc-only** (orange) — right lines, but no on-target finding reported the
     advisory's CWE: probably lucky overlap, not understanding.
   - **miss** (red) — the model reported findings but none on this bug.
   - **no run** (grey) — refused, incomplete, or absent.
   - **†** — the fix predates that model's training cutoff (memorization possible).
3. **Summary table** — recall with CI, **strict recall** (exact-only), loc-only and
   oversized-only counts (findings whose only overlap came from a location wider than
   the span cap — a gaming/vagueness signal), and *on-target findings*. On-target is
   **directional** precision: an off-target finding may be a real unseeded bug.
4. **Negative controls** — confirmed false positives and discrimination, when control
   runs exist (see above).
5. **Confidence calibration** — on-target rate split by the model's own reported
   confidence. A calibrated model's "high" beats its "low"; flat calibration means
   the confidence field carries no information.
6. **Pairwise McNemar** — exact test on paired per-case outcomes (refusals count as
   misses). p ≥ 0.05: the suite cannot distinguish that pair of models.

Stratify by difficulty (the matrix's `Diff.` column): the capability gap between
frontier models shows up almost entirely on the hard cases; everyone finds the easy ones.
