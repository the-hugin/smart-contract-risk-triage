# evm-risk-triage

Passive funds-at-risk triage for verified EVM contracts.

`evm-risk-triage` helps security researchers and auditors turn large sets of
verified smart contracts into a smaller manual review queue. It combines
Sourcify source intake, optional read-only liveness filtering, and static
money-path heuristics.

It is not an exploit framework and it is not a vulnerability oracle. A high
score means "review this first", not "confirmed vulnerable".

## Use Cases

- Prioritize verified contracts for manual audit.
- Find live contracts with balances or recent activity before spending review
  time on source code.
- Build a repeatable first-pass queue for bug bounty or client-authorized
  research.
- Preserve full static-signal recall while keeping the analyst-facing queue
  short.
- Regression-test detector changes against known false-positive patterns.

## Safety Boundary

The included tools are passive by design:

- no transactions;
- no fork exploit execution;
- no active probing of target applications;
- no credential handling;
- no automatic vulnerability claims.

Use it only for your own contracts, authorized audits, bug bounty work inside
program scope, or passive public-source research.

## Repository Layout

```text
scripts/
  smart-contract-batch-scan.py   Static source scanner.
  eth-sourcify-list.py           List Sourcify verified targets.
  eth-sourcify-intake.py         Download Sourcify source bundles.
  eth-live-contract-filter.py    Read-only balance/activity filter.
  run-eth-contract-batch.py      Sourcify intake + static scan.
  run-eth-live-batch.py          List + live filter + intake + scan.

tests/
  fixtures/                      Synthetic regression contracts.
  run_regression.py              Compile and detector regression check.

Dockerfile
docker-compose.yml
```

## Requirements

- Python 3.11 or newer.
- No third-party Python packages are required.
- Docker is optional.
- Live filtering needs a JSON-RPC endpoint. The default is a public Ethereum
  endpoint; for large batches, use your own rate-limited RPC provider.

## Quick Start

Run the regression suite:

```bash
python tests/run_regression.py
```

Scan local source files:

```bash
python scripts/smart-contract-batch-scan.py tests/fixtures --out-dir tmp/scan
```

On Windows PowerShell, use `py -3` if `python` does not resolve:

```powershell
py -3 .\tests\run_regression.py
py -3 .\scripts\smart-contract-batch-scan.py .\tests\fixtures --out-dir .\tmp\scan
```

## Typical Workflows

### 1. Scan A Local Source Tree

```bash
python scripts/smart-contract-batch-scan.py ./contracts --out-dir ./runs/local-scan
```

Useful options:

```bash
python scripts/smart-contract-batch-scan.py ./contracts \
  --out-dir ./runs/local-scan \
  --critical-limit 300 \
  --max-file-mb 4
```

### 2. Fetch Verified Sources From Sourcify And Scan

```bash
python scripts/run-eth-contract-batch.py \
  --chain-id 1 \
  --limit 100 \
  --run-dir ./runs/eth-mainnet-100 \
  --delay-seconds 0.35
```

You can also scan a known address list:

```bash
python scripts/run-eth-contract-batch.py \
  --chain-id 1 \
  --addresses-file ./input/addresses.txt \
  --run-dir ./runs/address-list
```

`addresses.txt` accepts one address per line. Lines may also use
`<chain_id>,<address>` for mixed-source files consumed by the lower-level intake
script.

### 3. Build A Live-Filtered Batch

This workflow lists recent Sourcify contracts, checks read-only liveness
signals, keeps the highest-priority live targets, downloads source, and scans:

```bash
python scripts/run-eth-live-batch.py \
  --chain-id 1 \
  --candidate-limit 5000 \
  --keep-limit 200 \
  --run-dir ./runs/eth-live-200 \
  --require-activity \
  --min-recent-logs 1 \
  --balance-score-weight
```

For a stricter batch:

```bash
python scripts/run-eth-live-batch.py \
  --chain-id 1 \
  --candidate-limit 50000 \
  --keep-limit 500 \
  --run-dir ./runs/eth-live-strict \
  --require-threshold-balance \
  --require-activity \
  --min-recent-logs 1 \
  --recent-blocks 2000 \
  --balance-score-weight \
  --request-delay 0.1
```

## Outputs

The static scanner writes:

- `contracts-manifest.jsonl` - files and source metadata seen by the scanner.
- `all-signals.jsonl` - every detector signal, including low-priority signals.
- `critical-review.md` - the analyst-facing prioritized queue.

The live filter writes:

- `live-targets.txt` - kept targets for source intake.
- `live-filter-results.jsonl` - all scored rows.
- `live-filter-summary.json` - aggregate filter metadata.

The Sourcify intake writes:

- `sources/` - downloaded source bundles.
- `sourcify-summary.json` - intake status and counts.
- `failures.jsonl` - recoverable fetch failures, if any.

## How To Read Findings

Each finding has:

- `severity`: queue priority, not proof of exploitability.
- `confidence`: detector confidence in the syntactic pattern.
- `score`: sorting weight for manual review.
- `category`: broad risk class such as `reentrancy`, `access-control`,
  `upgradeability`, `signature-replay`, `oracle`, or `token-transfer`.
- `funds_at_risk`: whether the pattern appears to touch value movement.
- `manual_check`: what an analyst should verify next.

Recommended review order:

1. Confirm the target is in scope.
2. Confirm the flagged file is runtime-relevant, not only bundled source.
3. Check current balance, token balances, and recent activity.
4. Check state preconditions such as initialized proxy slots, Safe threshold,
   AMM initialized state, owner/admin roles, nonce/domain guards, and claimed
   bitmaps.
5. Decide whether a minimal-impact proof is allowed by the relevant program or
   engagement rules.

## Scoring Model

The scanner prioritizes:

- withdraw, claim, redeem, sweep, rescue, and payout paths;
- call-before-accounting patterns;
- unprotected initialization and upgrade paths;
- delegatecall and low-level call surfaces;
- signature, oracle, and token-transfer accounting issues;
- runtime-relevant Sourcify metadata where available;
- live balance and activity signals when the live filter is used.

The scanner downgrades common false-positive classes when it sees patterns such
as:

- known admin or factory modifiers;
- Gnosis Safe already-initialized setup paths;
- nonzero EIP-1967 implementation slots from precheck data;
- initialized AMM pool state;
- standard helper libraries;
- fixed-recipient maintenance flows;
- user-owned claim accounting;
- checked low-level calls;
- Merkle/domain/nonce/deadline guards.

## Runtime Precheck Data

`smart-contract-batch-scan.py` accepts optional read-only precheck data:

```bash
python scripts/smart-contract-batch-scan.py ./sources \
  --out-dir ./runs/scan-with-precheck \
  --precheck-json ./precheck.json
```

The JSON should be keyed by contract address. It is used only to downgrade
known initialized-state false positives. It does not replace manual review.

## Docker

Build and run:

```bash
docker compose build
docker compose run --rm scanner --chain-id 1 --limit 10 --run-dir /runs/eth-mainnet-10
```

The compose file mounts:

- `./runs` to `/runs`;
- `./input` to `/input` as read-only.

## Development

Run regression before changing detector logic:

```bash
python tests/run_regression.py
```

Expected baseline:

```text
Scanned files: 14
Findings: 31
Severity: critical=2 high=2 medium=14 low=13 info=0
Regression OK
```

The two expected critical regression cases are synthetic:

- `FinanceBank.Collect` - call-before-accounting reentrancy pattern.
- `MockPoolManager.take` - unguarded external token movement pattern.

If a change alters these counts, update or add fixtures and explain why the new
behavior is safer.

## Responsible Use

Do not publish raw unresolved scan outputs against live third-party contracts as
confirmed vulnerabilities. The outputs are leads for manual analysis.

Before reporting anything externally, verify:

- authorization and scope;
- runtime/source match;
- current on-chain state;
- funds-at-risk and attacker preconditions;
- whether the issue is already known, accepted, patched, or out of scope.

## Limitations

- Static analysis is heuristic and intentionally conservative.
- Source bundles may contain non-runtime files.
- Public RPC endpoints can rate-limit, omit methods, or return inconsistent
  errors.
- The tool does not model full protocol economics.
- Severity labels are triage labels, not CVSS or bug bounty severity.

## License

Apache-2.0. See `LICENSE`.
