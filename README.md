# evm-risk-triage

Passive triage for verified EVM contracts with funds-at-risk prioritization.

This is not a vulnerability oracle and it does not execute exploits. It helps
an analyst build a smaller manual review queue from verified contract source
code, current balance/activity signals, and static money-path heuristics.

## What It Does

- Downloads verified contract source bundles from Sourcify.
- Optionally filters candidate contracts by read-only liveness signals:
  native ETH balance, selected ERC-20 balances, and recent logs.
- Scans local Solidity, Vyper, and Move-like source files for high-risk review
  patterns.
- Ranks findings into review artifacts instead of claiming exploitability.
- Keeps full recall in `all-signals.jsonl` while putting analyst attention on
  `critical-review.md`.

## What It Does Not Do

- It does not send transactions.
- It does not run fork exploits.
- It does not perform active probing of target applications.
- It does not prove reportability by itself.
- It should not be used outside authorized research, audits, or passive public
  source triage.

## Requirements

- Python 3.11 or newer.
- No third-party Python packages are required for the included scripts.
- Docker is optional.

## Quick Start

Scan local source files:

```powershell
py -3 .\scripts\smart-contract-batch-scan.py .\tests\fixtures --out-dir .\tmp\scan
```

Fetch a small Sourcify sample and scan it:

```powershell
py -3 .\scripts\run-eth-contract-batch.py --chain-id 1 --limit 10 --run-dir .\runs\eth-mainnet-10 --delay-seconds 0.35
```

Build a live-filtered passive batch:

```powershell
py -3 .\scripts\run-eth-live-batch.py --chain-id 1 --candidate-limit 1000 --keep-limit 50 --run-dir .\runs\eth-live-50 --require-activity --min-recent-logs 1
```

Run the regression suite:

```powershell
py -3 .\tests\run_regression.py
```

## Outputs

The scanner writes:

- `contracts-manifest.jsonl`: source files and metadata seen by the scanner.
- `all-signals.jsonl`: every detector signal, including low-priority signals.
- `critical-review.md`: the prioritized analyst review queue.

The live filter writes:

- `live-targets.txt`: kept targets for source intake.
- `live-filter-results.jsonl`: all scoring rows.
- `live-filter-summary.json`: aggregate filter metadata.

## Scoring Model

The score is a prioritization aid. A high score means "review first", not
"confirmed vulnerable". Current scoring favors:

- money movement paths such as withdraw, claim, redeem, sweep, and rescue;
- unprotected initialization and upgrade paths;
- call-before-accounting patterns;
- delegatecall, low-level call, signature, oracle, and accounting signals;
- verified source and runtime-relevant Sourcify metadata;
- current native/token balance and recent activity when the live filter is used.

Common false-positive classes are downgraded when the scanner sees guards such
as known admin modifiers, Safe initialization state, EIP-1967 implementation
slots, AMM initialized state, standard helper libraries, fixed-recipient flows,
user-owned claim accounting, or checked low-level calls.

## Safe Use

Use this tool for passive review, your own contracts, client-authorized audits,
or public-source research. Do not use it as a substitute for program scope,
legal authorization, manual code review, or responsible disclosure judgment.

Public scan outputs can include live contract addresses and analyst hypotheses.
Treat them as research notes and review before sharing.

## Docker

```powershell
docker compose build
docker compose run --rm scanner --chain-id 1 --limit 10 --run-dir /runs/eth-mainnet-10
```

## License

Apache-2.0. See `LICENSE`.
