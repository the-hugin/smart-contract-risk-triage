# Security Policy

## Scope

This project is a passive triage helper. It should not be used to send
transactions, exploit live systems, bypass access controls, or run active tests
against targets without authorization.

## Reporting Security Issues

If you find a security issue in this tool, open a private advisory or contact
the maintainer through the repository security channel. Do not include secrets,
private keys, raw authorization headers, cookies, or live exploit transaction
payloads in public issues.

## Handling Findings Produced By The Tool

Tool output is unverified until manually reviewed. Before reporting any finding
to a project or bug bounty program:

- confirm the target is in scope;
- confirm source/runtime reachability;
- confirm current state preconditions with read-only checks where appropriate;
- avoid collecting unnecessary personal data or secrets;
- use minimum-impact proof steps.
