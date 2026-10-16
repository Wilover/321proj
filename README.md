# AI-RDR — M5 incident response and AICM

Corrected implementation based on the supplied example. The response actions are
shared by a Wazuh adapter and a durable freeze/verify state machine. This is lab
code, not a claim of production readiness or validated sub-second containment.

AICM now stores incident cases, alerts, evidence references, response operations
and an append-only audit trail in SQLite. See [AICM usage](docs/aicm-usage.md) for
the case CLI, M6 integration contract and migration details, and
[design research](docs/aicm-research.md) for the source comparisons.

For manually stepped VS Code demonstrations and report evidence, use
[Four M5 implementation milestones](docs/manual-four-week-tests.md):
`python3 tools/manual_m5.py week1` (then week2, week3 and week4). Host changes are
simulated and labeled; `kernel` separately tests only a disposable real child.

## Development and tests

Use the existing `/workspace/321proj` checkout. No worktree is needed.
There are no pip dependencies. Target Ubuntu 22.04, Python 3.10–3.12, Linux with
`pidfd_open` and `pidfd_send_signal`, and both iptables/ip6tables backends. Python
3.13 removes `spwd`; account actions currently require Python 3.10–3.12.

```bash
cd /workspace/321proj
python3 -m unittest discover -s tests -v
```

Tests mock firewall and account changes. Kernel tests freeze/resume or terminate
only harmless `sleep` child processes they create. They do not require root.

## What changed

- Executable wrappers read bounded newline-delimited Wazuh JSON, send `check_keys`,
  flush stdout and require `continue` before acting. `abort` performs no action.
  Deletes release only their case's ownership. Diagnostics go to stderr.
- Required Case IDs replace `CASE-UNKNOWN`. PID, boot ID and process start ticks
  bind alerts and persisted state to the original process. Signals use pidfds.
- Freeze journals intent before signals, stops parents before discovering
  descendants, rejects overlapping process cases, and preserves pre-existing
  stopped processes. The worker recovers interrupted actions.
- Verification consumes attributed detector evidence. It does not infer causality
  from file timestamps or wait for stopped processes to generate fresh events.
- Positive evidence or root analyst approval is required before killing. Critical
  assets require analyst approval even with decoy evidence. Kill is irreversible.
- Isolation covers IPv4 and IPv6 INPUT/OUTPUT, allowing loopback, configured
  manager TCP traffic and controller-scoped SSH. It never allows all established connections. IP blocks
  cover both inbound source and outbound destination traffic.
- Resource leases are keyed by case. One case cannot remove another's isolation,
  block or account restriction. Thaw does not automatically remove network rules.
- Account restriction locks the local password and expires the account. Undo
  restores original lock/expiry metadata. It never terminates existing sessions
  or stores password hashes. Session termination would be a separate irreversible
  policy and is deliberately excluded.
- ARM snapshots, response projections, transition audits and outbox entries commit
  atomically in SQLite with durable sync, serialized by the endpoint file lock.
  Corrupt state fails closed. Failed firewall mutations retain intent for worker
  reconciliation. Existing JSON state is imported once and retained as an archive.
- ML `response_mode=alert_only` prevents automatic actions from that signal alone.
  Independently attributed decoy evidence retains its automatic path; optional
  `require_approval` adds a process-containment gate alongside `critical_asset`.

## Detector contract — agree with M1, M2, M3 and M6

Wazuh `parameters.alert.data` should contain an incident `case_id`. If absent,
AICM derives a UUID from immutable process identity or the source alert identity.
Supply an explicit shared Case ID to group independent process roots. Process actions require:

```json
{
  "case_id": "CASE-001",
  "pid": 4128,
  "start_ticks": 123456,
  "boot_id": "endpoint-linux-boot-uuid",
  "risk_score": 0.75,
  "evidence": {
    "type": "decoy_write",
    "event_id": "audit-event-123",
    "pid": 4128,
    "start_ticks": 123456,
    "boot_id": "endpoint-linux-boot-uuid"
  }
}
```

`evidence` is optional for freeze; the decoy evidence shown authorizes containment
on a noncritical endpoint. Evidence must identify an actual registered-decoy write,
collected by M3/M1. This module trusts the privileged Wazuh/detector route; it does
not authenticate arbitrary JSON or independently validate the decoy registry.
Do not expose its input as a public endpoint. Process identity must be captured at
event collection time; guessing the current identity for a delayed PID is unsafe.
New attributed evidence can upgrade an already frozen case.

Block requires `src_ip` (IPv4 or IPv6), disable requires `username`. Each process
root receives its own deterministic operation UUID; a case may contain several
operations. Wazuh alerts should also carry `id`, `agent.id`, and a timezone-aware
`timestamp`, used to deduplicate and retain source timing. An alert with an ID but
no timestamp is rejected. Legacy alerts without IDs remain actionable, with an
explicit `alert_recorded=false` entry. Scores in `[0.60, 0.90)` select the candidate freeze path; these are
experimental thresholds. A high score alone does not authorize irreversible kill.
Decoy evidence may select the kill path without waiting for verification timeout.
Independent isolation can execute directly from a high-confidence Wazuh rule.

An adapter must forward M2's `response_mode` into `alert.data.response_mode`;
omitting the field retains the legacy candidate policy. `alert_only` alone records
the alert/case without mutating the host. A separately attributed `decoy_write`
retains the automatic path and does not need an ML score. `require_approval=true`
adds an extra process-containment gate; its default is false.

## Ubuntu/Wazuh lab deployment

For the full file-location map, configuration values, hardcoded limits, manager
setup and staged checks, follow [Ubuntu deployment](docs/ubuntu-deployment.md).

Use a disposable endpoint VM and snapshot. Replace the example manager address
and set `agent_id` to this endpoint's Wazuh ID; configure whether it is critical. Keep config and scripts root-owned
and nonwritable by monitored users; state must be root-only. Reserve `AI_RDR_*`
chains exclusively for this application, and do not mix firewall backends.

```bash
sudo install -d -m 700 /etc/ai-rdr /var/lib/ai-rdr /var/log/ai-rdr
sudo install -m 600 config/lab.example.json /etc/ai-rdr/config.json
# Edit /etc/ai-rdr/config.json for this endpoint before enabling responses.
sudo install -o root -g wazuh -m 750 ai_rdr_*.py freeze_verify_manager.py /var/ossec/active-response/bin/
sudo install -m 644 systemd/ai-rdr-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ai-rdr-worker.service
```

Merge `ossec.conf.example` into the manager configuration and agree rule IDs and
payload fields before restarting Wazuh. The commands use `location=local`, so
executables/config/worker belong on each responding endpoint. The freeze command
has no Wazuh timer: its deadline belongs to the worker. Block/account timer values
are examples, not recommended operational limits. Isolation requires explicit undo.

The default example has a 3-second **inconclusive-thaw** policy. This prioritizes
availability and can resume malicious activity; timeout is never logged as benign.
Alternatively, set `timeout_policy` to `review`: the deadline records REVIEW and
keeps processes stopped pending analyst action. That policy has no automatic upper
bound on disruption. Neither choice is universally safe; choose explicitly for
your experiment. A worker outage delays deadlines; systemd restarts it, but does
not provide a hard real-time guarantee. Monitor service health during experiments.

Analyst commands (root-only, with recorded reasons):

```bash
sudo python3 /var/ossec/active-response/bin/ai_rdr_response.py status
sudo python3 /var/ossec/active-response/bin/ai_rdr_response.py approve CASE-001 --reason "Confirmed malicious"
sudo python3 /var/ossec/active-response/bin/ai_rdr_response.py thaw CASE-001 --reason "Confirmed benign"
sudo python3 /var/ossec/active-response/bin/ai_rdr_response.py undo CASE-001 --reason "Incident resolved"
```

For a case with several active process roots, append `--operation <operation-id>`
to `approve` or `thaw`. Inspect IDs through `ai_rdr_case.py show CASE-001`.

`approve` performs isolation and termination. `thaw` resumes only processes this
case stopped. `undo` releases reversible firewall/account leases; it cannot restore
terminated processes and does not resume frozen processes.

## Verification still required in the lab

1. Send real detector alerts through the installed Wazuh manager/agent; check
   continue/abort handling, duplicate alerts, rule targeting and timer deletes.
2. On a disposable VM, verify permitted manager traffic and forbidden fresh AND
   existing IPv4/IPv6 traffic. There is no cloud firewall readiness claim here.
3. Check new password and SSH-key logins are refused for the disposable expired
   account using your actual PAM/sshd policy. Existing sessions are not revoked.
4. Restart the worker during freeze; verify deadline recovery and audit records.
5. Exercise concurrent cases and partial backend failures; undo must preserve
   unrelated rules and pre-existing account state.

Network isolation covers local INPUT/OUTPUT, not routed/bridged/container FORWARD
traffic. Manager connections are intentionally permitted. Already queued writes,
uninterruptible kernel I/O, independent malicious processes and reparented children
may outlive process-tree containment. Discovery is bounded to 128 targets and two
seconds; it is not an atomic cgroup freeze. Use controlled process trees for the
candidate experiment; cgroup-v2 containment is a separate enhancement.
Account expiry assumes local accounts and compatible PAM enforcement; directory
accounts and active session revocation are unsupported. Concurrent administrative
changes to password-lock markers cannot always be distinguished from our changes;
coordinate administration while a case owns an account lease. Firewall commands
are individually bounded but sequential; a large tree/queue can delay other cases.
State retains completed cases for inspection and currently has no retention policy.
External threat-intelligence verification is not implemented; M4 enrichment is not
on the critical path. Root compromise is outside this module's protection boundary.

## Evaluation

The SQLite audit records UTC timestamps, stable event/request/operation IDs, actors,
case sequences, case changes and local action timings. `ai_rdr_case.py export` emits
a JSON report. The old `audit_log` setting is retained for compatibility but no
longer receives writes. These are local action timings, not end-to-end attack latency.
M6 must correlate attack/decoy time, alert time, effective-action time and damage
counters. Use p50/p95/p99, deadline misses, containment/undo success, benign
disruption, files/bytes modified, and descendant escape rate. Compare immediate
containment against candidate verification windows of 1, 3 and 5 seconds using
identical workloads. The design's `<1 s` decoy and `<10 s` behavioural goals remain
unverified; a three-second verification window must fit the remaining total budget.

Protocol reference:
https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
