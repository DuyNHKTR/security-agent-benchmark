# Claude Code Runbook

1. Install the Claude Code version pinned by the profile and log in with the intended paid Claude subscription. Do not set or use `ANTHROPIC_API_KEY` for benchmark runs.
2. Run `npm run bench -- run claude prepare <case> --profile <profile> --suite <suite.yaml>`.
3. Open the generated `CLAUDE_RUN.md` and execute its launch command.
4. Paste all of `prompt.txt` as the first message exactly once.
5. Do not answer questions or send follow-up messages. The prompt requires Claude to make assumptions and continue autonomously.
6. When `COMPLETED` exists and Claude returns, exit and run `bench run validate`.
7. Importing Claude session JSONL is optional for token-efficiency analysis. Cost does not depend on Claude tokens: it is allocated from the configured monthly subscription fee divided by expected scans per month.

Claude launches locally with safe mode and automatic permission handling because subscription authentication belongs to the interactive Claude Code session. Safe mode prevents local memories, project instructions, plugins, and MCP configuration from changing the benchmark. The model is selected by the launch profile, not mentioned in the prompt.

Claude may execute repository commands on the host. Only benchmark repositories you trust to execute, or run the benchmark workstation inside a disposable VM. Codex retains the Docker and egress-proxy path.

If the process crashes, preserve the run directory and transcript. Mark the attempt incomplete; do not silently restart it as the same primary run. A resumed diagnostic run must be labeled separately from benchmark results.
