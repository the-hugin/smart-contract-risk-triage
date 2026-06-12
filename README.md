# smart-contract-risk-triage

Passive triage for smart-contract review queues.

The repo has two parts:

- EVM tooling: Sourcify intake, balance/activity filtering, static money-path
  scan, runtime prechecks, and continuous monitors.
- Solana tooling: BPF Upgradeable Loader monitoring with conservative
  value-proximity checks.

The output is a review queue. It is not a confirmed-vulnerability feed.

## Boundaries

The tools do not send transactions, simulate exploits, brute force endpoints, or
collect credentials. They use public source metadata and read-only RPC calls.

Use them for your own contracts, authorized audits, in-scope bug bounty work, or
passive public-source research. Treat every finding as a lead until a human
checks scope, runtime state, exploitability, and program rules.

## What It Covers

EVM:

- Sourcify verified-source listing and download.
- Native and ERC20 balance filters.
- Recent log activity filters.
- Static source triage for withdraw, claim, redeem, sweep, rescue, payout,
  reentrancy, init/upgrade, delegatecall, signature, oracle, and token-transfer
  patterns.
- Read-only prechecks for common false positives: EIP-1967 implementation or
  beacon slots, Gnosis Safe threshold, AMM pool state, and owner calls.
- Config-driven monitors for Ethereum, Base, Arbitrum, Optimism, Polygon, BNB
  Smart Chain, Avalanche, Linea, Scroll, zkSync Era, Gnosis, Blast, Mantle, and
  Celo.

Solana:

- BPF Upgradeable Loader signature polling.
- Deploy, upgrade, close, and authority-change event extraction.
- Program and program-data account metadata.
- Recent-transaction value context for SOL, WSOL, USDC, and USDT.
- Suppression for common noise: WSOL token-account lamports, on-curve wallets,
  signed token owners, program/program-data rent, and known shared value
  accounts.

Solana value context is deliberately weak. A large token account seen near a
program is not proof that the program controls the funds.

## Layout

```text
config/
  smart-contract-evm-chains.json
  smart-contract-non-evm-chains.json

scripts/
  smart-contract-batch-scan.py
  eth-sourcify-list.py
  eth-sourcify-intake.py
  eth-live-contract-filter.py
  eth-runtime-precheck.py
  eth-high-value-triage.py
  eth-continuous-monitor.py
  evm-monitor-config.py
  solana-program-monitor.py
  non-evm-monitor-config.py
  run-eth-contract-batch.py
  run-eth-live-batch.py

docs/
  smart-contract-chain-coverage.md

tests/
  fixtures/
  run_regression.py
```

See `ROADMAP.md` for the next chain families and detector work.

## Requirements

- Python 3.11+
- No Python package dependencies
- Optional Docker
- JSON-RPC endpoints for live filters and monitors

Public RPC endpoints work for small checks. For continuous monitoring or large
batches, use an endpoint with known rate limits.

## Quick Start

Run the regression suite:

```bash
python tests/run_regression.py
```

Scan local source files:

```bash
python scripts/smart-contract-batch-scan.py tests/fixtures --out-dir tmp/scan
```

Windows:

```powershell
py -3 .\tests\run_regression.py
py -3 .\scripts\smart-contract-batch-scan.py .\tests\fixtures --out-dir .\tmp\scan
```

## EVM Batch Workflows

Scan a local source tree:

```bash
python scripts/smart-contract-batch-scan.py ./contracts --out-dir ./runs/local-scan
```

Download verified sources from Sourcify and scan them:

```bash
python scripts/run-eth-contract-batch.py \
  --chain-id 1 \
  --limit 100 \
  --run-dir ./runs/eth-mainnet-100 \
  --delay-seconds 0.35
```

Scan an address list:

```bash
python scripts/run-eth-contract-batch.py \
  --chain-id 1 \
  --addresses-file ./input/addresses.txt \
  --run-dir ./runs/address-list
```

`addresses.txt` accepts one address per line. The lower-level intake script also
accepts `<chain_id>,<address>` lines.

Build a live-filtered queue:

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

Stricter run with runtime prechecks and a ranked triage report:

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
  --runtime-precheck \
  --high-value-triage \
  --request-delay 0.1
```

For non-mainnet EVM chains, pass token filters explicitly:

```bash
python scripts/run-eth-live-batch.py \
  --chain-id 8453 \
  --rpc-url https://base-rpc.publicnode.com \
  --candidate-limit 10000 \
  --keep-limit 200 \
  --run-dir ./runs/base-live \
  --eth-min-wei 300000000000000000 \
  --token 0x4200000000000000000000000000000000000006=WETH:18:0.3 \
  --token 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913=USDC:6:500
```

Check token addresses, decimals, and thresholds before relying on a non-mainnet
run. The defaults are a 500 USD-style value filter, not a price oracle.

## Continuous EVM Monitor

List configured chains:

```bash
python scripts/evm-monitor-config.py list
```

Probe one chain:

```bash
python scripts/evm-monitor-config.py probe --only ethereum
```

Render systemd units:

```bash
python scripts/evm-monitor-config.py systemd \
  --out-dir ./tmp/systemd-evm \
  --only ethereum \
  --remote-root /opt/smart-contract-risk-triage \
  --python /usr/bin/python3 \
  --no-telegram
```

Run one cycle directly:

```bash
python scripts/eth-continuous-monitor.py \
  --chain-id 1 \
  --chain-label Ethereum \
  --workspace . \
  --state-dir runs/monitor-state/ethereum \
  --rpc-url https://ethereum-rpc.publicnode.com \
  --seed-if-empty \
  --delete-uninteresting
```

Telegram alerts are off by default in the public config. To enable them, set:

- `SMART_CONTRACT_ALERT_BOT_TOKEN`
- `SMART_CONTRACT_ALERT_CHAT_ID`

The chat id must be a positive numeric private chat id. The monitor rejects
channel and group-style ids before calling `sendMessage`.

## Solana Monitor

List non-EVM chains:

```bash
python scripts/non-evm-monitor-config.py list
```

Probe Solana RPC:

```bash
python scripts/non-evm-monitor-config.py probe --only solana
```

Run one loader-monitor cycle:

```bash
python scripts/solana-program-monitor.py \
  --workspace . \
  --state-dir runs/monitor-state/solana \
  --rpc-url https://api.mainnet-beta.solana.com \
  --candidate-limit 120 \
  --transaction-batch-size 1 \
  --allow-cursor-skip \
  --seed-if-empty \
  --delete-uninteresting
```

Public Solana RPC can rate-limit `getTransaction`. Keep the window small, use
delays, and read `cursorSkipped=true` as "latest bounded window processed", not
as historical completeness.

## Outputs

Static scanner:

- `contracts-manifest.jsonl`
- `all-signals.jsonl`
- `critical-review.md`

Live filter:

- `live-targets.txt`
- `live-filter-results.jsonl`
- `live-filter-summary.json`

Runtime and high-value EVM triage:

- `runtime-precheck.json`
- `triage/high-value-triage.md`
- `triage/high-value-triage.jsonl`

Sourcify intake:

- `sources/`
- `sourcify-summary.json`
- `failures.jsonl`

Continuous monitors write compact status and event files under `runs/`. With
`--delete-uninteresting`, they delete run directories that have no reviewable
signals.

## Reading Findings

For EVM findings:

- `severity` is queue priority.
- `confidence` is detector confidence in the pattern.
- `score` is sorting weight.
- `category` is the risk class.
- `funds_at_risk` means the pattern appears to touch value movement.
- `manual_check` says what to verify next.

Review order:

1. Confirm scope.
2. Confirm the flagged file is runtime-relevant.
3. Check current native and token balances.
4. Check state preconditions: proxy slots, Safe threshold, AMM state,
   owner/admin roles, nonce/domain guards, claimed bitmaps.
5. Decide whether program rules allow any proof step.

For Solana, do not escalate on value alone. Check token owner, signers, PDA or
source relation, upgrade authority, and project context.

## Runtime Precheck Data

Generate precheck data from a target list:

```bash
python scripts/eth-runtime-precheck.py \
  --targets-file ./runs/eth-live/live-filter/live-targets.txt \
  --out ./runs/eth-live/runtime-precheck.json \
  --rpc-url https://ethereum-rpc.publicnode.com
```

Use it during a scan:

```bash
python scripts/smart-contract-batch-scan.py ./sources \
  --out-dir ./runs/scan-with-precheck \
  --precheck-json ./runs/eth-live/runtime-precheck.json
```

Prechecks only downgrade known false-positive classes. They do not prove the
contract is safe.

## Docker

```bash
docker compose build
docker compose run --rm scanner --chain-id 1 --limit 10 --run-dir /runs/eth-mainnet-10
```

Mounted paths:

- `./runs` -> `/runs`
- `./input` -> `/input` read-only

## Development

Run these before changing detector logic:

```bash
python tests/run_regression.py
python scripts/evm-monitor-config.py list
python scripts/non-evm-monitor-config.py list
python scripts/public-sanity-check.py
```

Expected baseline:

```text
Scanned files: 14
Findings: 31
Severity: critical=2 high=2 medium=14 low=13 info=0
Regression OK
```

Expected synthetic critical cases:

- `FinanceBank.Collect`
- `MockPoolManager.take`

If the counts change, update or add fixtures and explain the behavior change in
the commit.

## Responsible Use

Do not publish unresolved output as a confirmed vulnerability. Before reporting
anything externally, verify authorization, runtime/source match, current state,
attacker preconditions, duplicate status, and program rules.

## Limits

- Static analysis is heuristic.
- Runtime prechecks only cover known false-positive classes.
- Token filters are chain-specific and can go stale.
- Source bundles can include non-runtime files.
- Public RPC endpoints can rate-limit or omit methods.
- The tool does not model full protocol economics.
- Solana support is loader-event monitoring and value-proximity triage, not a
  Rust/Anchor analyzer.
- Severity labels are triage labels, not CVSS or bounty severity.

## License

Apache-2.0. See `LICENSE`.
