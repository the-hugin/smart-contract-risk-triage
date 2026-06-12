FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY config/smart-contract-evm-chains.json /app/config/smart-contract-evm-chains.json
COPY config/smart-contract-non-evm-chains.json /app/config/smart-contract-non-evm-chains.json
COPY scripts/smart-contract-batch-scan.py /app/scripts/smart-contract-batch-scan.py
COPY scripts/eth-sourcify-intake.py /app/scripts/eth-sourcify-intake.py
COPY scripts/eth-sourcify-list.py /app/scripts/eth-sourcify-list.py
COPY scripts/eth-live-contract-filter.py /app/scripts/eth-live-contract-filter.py
COPY scripts/eth-runtime-precheck.py /app/scripts/eth-runtime-precheck.py
COPY scripts/eth-high-value-triage.py /app/scripts/eth-high-value-triage.py
COPY scripts/eth-continuous-monitor.py /app/scripts/eth-continuous-monitor.py
COPY scripts/evm-monitor-config.py /app/scripts/evm-monitor-config.py
COPY scripts/solana-program-monitor.py /app/scripts/solana-program-monitor.py
COPY scripts/non-evm-monitor-config.py /app/scripts/non-evm-monitor-config.py
COPY scripts/run-eth-contract-batch.py /app/scripts/run-eth-contract-batch.py
COPY scripts/run-eth-live-batch.py /app/scripts/run-eth-live-batch.py

VOLUME ["/runs", "/input"]

ENTRYPOINT ["python", "/app/scripts/run-eth-contract-batch.py"]
CMD ["--chain-id", "1", "--limit", "5000", "--run-dir", "/runs/eth-mainnet-5000"]
