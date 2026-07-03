# Codex Runbook

1. Export a dedicated `OPENAI_API_KEY`.
2. Build the benchmark and Docker image: `npm install`, `npm run build`, then `docker build -t security-agent-benchmark-agent:local -f docker/Dockerfile .`.
3. Prepare pinned fixtures with `npm run bench -- suite prepare <suite.yaml>`.
4. Run each case with `npm run bench -- run codex <case> --profile <profile> --suite <suite.yaml>`.

The runner calls `codex exec` with user configuration and repository rules disabled, an ephemeral session, the canonical output schema, JSONL telemetry, and no approval prompts inside the isolated container. It validates the final message before marking the run complete.

Do not add model-specific prompt text or tools to a profile. A profile selects only adapter, model identifier, pricing key, and execution mode.
