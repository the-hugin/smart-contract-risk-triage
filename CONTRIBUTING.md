# Contributing

Contributions should improve triage quality, reduce false positives, or make
outputs easier to review.

Preferred changes:

- focused detector improvements with a regression fixture;
- new false-positive suppressions with a concrete example;
- safer defaults for rate limits, paths, and output handling;
- documentation that clarifies passive use and manual verification.

Avoid:

- exploit automation;
- live transaction execution;
- target-specific findings or addresses from unresolved reports;
- large source dumps or scan outputs;
- changes that raise severity without a regression fixture.

Before opening a pull request, run:

```powershell
py -3 .\tests\run_regression.py
py -3 .\scripts\evm-monitor-config.py list
py -3 .\scripts\non-evm-monitor-config.py list
py -3 .\scripts\public-sanity-check.py
```

CI also renders sample systemd units with Telegram disabled. Do not commit local
run directories, unresolved target evidence, private VPS paths, or alert
credentials.
