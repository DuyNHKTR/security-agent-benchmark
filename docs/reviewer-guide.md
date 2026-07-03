# Reviewer Guide

Reviewers must not inspect `runs/`, `private-map.json`, provider logs, cost, or model metadata before adjudication. The CLI shows a shared fixture path for direct repository validation.

Score what is demonstrated, not what might be true. Accept a finding only when the cited code exists and the stated attacker-controlled path is reachable under its documented preconditions. Reject speculative sinks without a viable source-to-sink chain. Mark semantically equivalent findings as duplicates even if titles or CWE labels differ.

Run `bench review start` independently under two reviewer IDs. The CLI resumes from append-only JSONL files. `bench review adjudicate` automatically averages close agreements and asks an adjudicator to resolve material disagreements. Do not reveal profile identity until adjudication files are complete.
