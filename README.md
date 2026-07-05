# Security Agent Benchmark

Reproducible, harness-neutral benchmark for exploitability-focused repository security assessment. The initial profiles target Claude Fable, Claude Opus, and GPT-5.5, while adapters and model profiles are independently extensible.

Two evaluation modes share the same runner:

- **Quality review** (default) — blinded human reviewers score finding quality and the
  pipeline computes validated security value per dollar. Measures how *good* a model's
  findings are; has no recall.
- **Ground-truth detection** — point a case at a security-**fix** commit; the harness
  scans the commit before it, derives the answer key from the fix diff, and scores
  **recall and localization** automatically. Measures how much a model *finds*. No manual
  vulnerability labeling required. See [Ground-truth detection](docs/ground-truth.md).

## Requirements

- Node.js 22+
- Git
- Docker Desktop / Docker Engine with Compose for Codex
- A dedicated `OPENAI_API_KEY` for Codex
- Claude Code logged into a paid Claude subscription; Claude API keys are not used

## Setup

```powershell
npm install
npm run build
docker build -t security-agent-benchmark-agent:local -f docker/Dockerfile .
Copy-Item configs/suites/example.yaml configs/suites/enterprise.yaml
```

Edit `enterprise.yaml` with two Git URLs, immutable full commit SHAs, model profiles, and a versioned pricing catalog. Never benchmark a moving branch.

## Run

```powershell
npm run bench -- suite prepare configs/suites/enterprise.yaml
npm run bench -- run codex simple --profile codex-gpt-5-5 --suite configs/suites/enterprise.yaml
npm run bench -- run claude prepare simple --profile claude-fable --suite configs/suites/enterprise.yaml
```

The Claude command creates `CLAUDE_RUN.md` and `prompt.txt` in a new run directory. It uses the local Claude Code subscription session, not `claude -p` or the Anthropic API. Follow the generated command, paste the prompt once, and leave the agent running until it writes `COMPLETED`.

```powershell
npm run bench -- run validate <claude-run-directory> --suite configs/suites/enterprise.yaml
npm run bench -- run usage-from-transcript <claude-run-directory> <claude-session.jsonl> --suite configs/suites/enterprise.yaml
npm run bench -- review build --suite configs/suites/enterprise.yaml
npm run bench -- review start --reviewer reviewer-a --suite configs/suites/enterprise.yaml
npm run bench -- review start --reviewer reviewer-b --suite configs/suites/enterprise.yaml
npm run bench -- review adjudicate --suite configs/suites/enterprise.yaml
npm run bench -- report build --suite configs/suites/enterprise.yaml
```

Reports are written as JSON, CSV, and HTML under `runs/<suite>/reports/`.

Run the same commands for `simple` and `complex`. Use both Claude profiles with `run claude prepare`, and the Codex profile with `run codex`, producing six primary runs before building the review queue.

## Documentation

- [Architecture](docs/architecture.md)
- [Methodology](docs/methodology.md)
- [Ground-truth detection](docs/ground-truth.md)
- [Codex runbook](docs/run-codex.md)
- [Claude Code runbook](docs/run-claude-code.md)
- [Adding a model or harness](docs/adding-adapters.md)
- [Reviewer guide](docs/reviewer-guide.md)
