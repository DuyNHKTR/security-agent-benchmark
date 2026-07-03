# Adding Models and Harnesses

## Existing harness

Add a YAML profile under `configs/models/` and reference it from the suite. The profile sets `id`, `adapter`, `model`, `pricing_key`, `cost_mode`, `execution`, and optionally a pinned `harness_version`. Add token rates or subscription allocation inputs to the suite's immutable pricing snapshot.

## New harness

Implement an adapter with four responsibilities:

1. Launch or generate a one-paste launch package.
2. Deliver the unmodified rendered semantic prompt.
3. Persist a schema-conforming `report.json` and raw logs.
4. Normalize token telemetry into input, output, cache-read, and cache-write counts with provenance.

Do not add harness capabilities, model names, special reasoning instructions, or different finding limits to the prompt. Add contract tests proving the adapter emits the same run artifacts and rejects malformed output. Register the adapter type in `src/types.ts` and dispatch it in `src/cli.ts`.
