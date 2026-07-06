# Codex Runbook

The default `codex-gpt-5-5` profile runs Codex on your **ChatGPT subscription**, locally and fully automated (no `OPENAI_API_KEY`, no Docker). Codex runs everywhere non-interactively, so — unlike the Claude route — no human is in the loop.

1. Log in once with the intended ChatGPT subscription: `codex login`. Do not export `OPENAI_API_KEY` (for local runs the runner strips it so it cannot shadow the subscription login).
2. Build the benchmark: `npm install`, `npm run build`.
3. Prepare pinned fixtures with `npm run bench -- suite prepare <suite.yaml>`.
4. Run each case with `npm run bench -- run codex <case> --profile <profile> --suite <suite.yaml>`.

The runner calls `codex exec` with user configuration and repository rules disabled, an ephemeral session, the canonical output schema, JSONL telemetry, and no approval prompts. Local runs use Codex's own `workspace-write` sandbox (writes confined to the run's target directory); use `gpt-5.5` (not `gpt-5.5-codex`, which ChatGPT-account auth rejects). It validates the final message before marking the run complete.

**Isolation note:** local execution runs the target repo's code on the host under Codex's `workspace-write` sandbox — weaker than the Docker path. Since the Claude route already runs locally, run the benchmark workstation inside a disposable VM.

**API-key / Docker variant (optional).** For stronger isolation with a pay-per-token API key instead of the subscription, set `execution: docker` and `cost_mode: token` in the profile, export `OPENAI_API_KEY`, and build the image: `docker build -t security-agent-benchmark-agent:local -f docker/Dockerfile .`. Codex then runs inside the container (cap-dropped, egress-allowlisted).

Do not add model-specific prompt text or tools to a profile. A profile selects only adapter, model identifier, pricing key, and execution mode.
