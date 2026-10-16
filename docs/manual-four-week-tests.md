# M5 manual testing in VS Code — four implementation milestones

Use this to run M5 yourself, inspect outputs and collect evidence for your report.
The week names group four implementation milestones; they do not assert that tests
were performed in four past calendar weeks. Enter your actual dates and results.
The implementation and tools are original M5 code; no central backend is replaced.

## Environment and controls

Open `321proj` in VS Code on Ubuntu, through Remote SSH to Ubuntu, or in WSL2
Ubuntu. Native Windows Python cannot run the Linux runtime (`fcntl`, `/proc`, etc.).
Use Python 3.10–3.12, your normal user, and no sudo. No pip dependencies are needed
for these demonstrations. The existing regression suite runs with:

```bash
/usr/bin/python3 -m unittest discover -s tests -v
```

The four weekly demonstrations run **real M5 logic and SQLite against an in-memory
host model**. Every signal, firewall command and account command is labeled
`[SIMULATED HOST]`. They do not call SSH, Wazuh, Flask, Infisical or OpenSearch,
and do not change real firewall rules, users or unrelated processes.

The separate `kernel` demonstration really freezes/resumes/terminates only one
disposable child it creates. It refuses root and rejects OS firewall/account
commands. Run it on Ubuntu/WSL2 after the simulations.

## Run and debug

In the VS Code terminal, from the repository root:

```bash
/usr/bin/python3 tools/manual_m5.py week1
/usr/bin/python3 tools/manual_m5.py week2
/usr/bin/python3 tools/manual_m5.py week3
/usr/bin/python3 tools/manual_m5.py week4
```

Each command starts a fresh session. Press Enter at each STEP, examine INPUT,
PROTOCOL, simulated commands, OBSERVED and PASS/FAIL, and take screenshots.
`continue` in the protocol output is an emulated Wazuh check-keys reply, not analyst
approval. Ctrl+C records an incomplete session. Failures exit nonzero.

Alternatively, use **Terminal → Run Task** and choose an `M5:` task. For breakpoints,
use the optional VS Code Python Debugger extension, select **M5: Debug a manual
milestone**, press F5 and choose the milestone. The terminal commands work without
the debugger extension. Useful breakpoint locations:

- `ai_rdr_response.py`: `_wazuh` after policy evaluation and before mutation.
- `ai_rdr_policy.py`: `automatic_allowed` / `attributed_decoy`.
- `freeze_verify_manager.py`: `freeze`, `tick`, `contain`, `thaw`.
- `ai_rdr_actions.py`: `reversible` and firewall rule construction.
- `ai_rdr_aicm.py`: `save_state` and `_event` transaction writes.

Breakpoints inside freeze/verification consume real timeout budgets. A long pause
can intentionally trigger rollback; do not use debug-paused runs as latency
measurements. The Enter prompts pause outside those critical sections.

## Week 1 — executable response actions

Run `week1`. Four manually advanced steps exercise:

| Step | Inspect in the terminal | Evidence to capture |
|---|---|---|
| Isolate and undo | IPv4/IPv6 INPUT/OUTPUT chains; controller-only SSH and manager exceptions; chain removal | Rule construction and preservation of unrelated model rules |
| Kill | Attributed synthetic decoy evidence, SIGSTOP then SIGKILL, KILLED operation | Irreversible process result; isolation lease separately removed |
| IP block and undo | Inbound source and outbound destination DROP; deletion | Both directions and undo |
| Account restriction/restore | `usermod -L -e 1`, then original lock/expiry restored | Before/after metadata; no claim about actual PAM login |

Representative text (illustrative; your run is authoritative):

```text
[SIMULATED HOST] iptables -w 1 -A AI_RDR_ISO_IN -s 192.0.2.63 -p tcp --dport 22 -j ACCEPT
[SIMULATED HOST] SIGKILL pid=4101
OBSERVED: {"address": "192.0.2.99", "directions": ["INPUT", "OUTPUT"], "undo": "rules removed"}
PASS: Block IP and undo
```

Report this as tested response logic with simulated system boundaries. It does
not prove packet filtering on the target VM or real account/session revocation.

## Week 2 — freeze, verify, automatic decoy and optional approval

Run `week2`. Pause and inspect these transitions:

1. A synthetic candidate score 0.75 stops a parent and child: FROZEN.
2. The tool explicitly injects an expired logical deadline, calls the worker tick
   and resumes them: THAWED, disposition still **undetermined**. This avoids
   confusing a controlled timeout test with a measured production latency.
3. Independent attributed decoy evidence triggers automatic kill/isolation even
   when the accompanying ML flag is `alert_only`. No ML score or human approval is
   required for that independent decoy decision.
4. Enabling `require_approval` leaves another confirmed process in REVIEW, stopped
   but not killed.
5. Press Enter to execute the explicit demonstration approval; the operation
   proceeds to KILLED and records a synthetic analyst identity/reason.

Capture both automatic and optional-approval results. The default decoy route is
automatic; `require_approval=true` and `critical_asset=true` add a process-containment
gate. These do not gate independently requested isolate/block/account actions.
Do not claim that the synthetic evidence is an actual M3/Wazuh detection.

## Week 3 — case record and audit trail

Run `week3`:

1. Create and assign a case, moving it from open to investigating.
2. Deliver two unique source alerts and one retry. Observe three deliveries but
   two stored alerts, plus a redacted dummy credential field.
3. Attempt a stale case update and direct audit deletion. Both must be rejected.
   Inspect numbered audit events, actor and outcome.
4. Resolve/close the synthetic case and verify a SQLite backup has identical history.

Capture the case record, audit ordering, rejection output and backup result. A
benign disposition here is an explicit test-case update, not inferred from timeout.
The triggers protect ordinary SQL updates/deletes; they do not defeat root tampering.

## Week 4 — local policy and integration safeguards

Run `week4`:

- An ML-only `alert_only` event records a case/alert but creates no response
  operation and sends no simulated signal/command.
- PID reuse changes a process identity. Thaw must refuse to signal the replacement.
- Two cases share isolation. Releasing the first retains it; releasing the final
  owner removes it.
- Deliver an outbox event to another local store, emulate a lost acknowledgement,
  retry it and then acknowledge. The event is imported once.

The last step is **local method-call delivery**, not a network test. The receiver
imports history only; central case/alert/operation synchronisation remains pending.
The PID-reuse example deliberately retains a failed THAWING record for inspection.

## Optional real Linux process evidence

```bash
/usr/bin/python3 tools/manual_m5.py kernel
```

This creates a harmless Python child running `time.sleep`, shows its actual PID
and `/proc` state, sends SIGSTOP, waits for your Enter, resumes it, then freezes
and terminates that same child with explicit test approval and `isolate=False`.
The final return code must be `-9`. Cleanup removes the child even on Ctrl+C.
No root privileges, firewall/account mutations or external hosts are used.

Capture the actual PID, stopped/running states and termination result. This is real
kernel/process evidence, but still not ransomware detection or network containment.

## Files saved for your report

Every run creates a fresh `artifacts/manual-m5/<UTC-time>-<milestone>-<suffix>/`:

| File | Contents |
|---|---|
| `terminal.txt` | Captured tool output, commands and observations (typed Enter prompts are not copied) |
| `results.json` | Actual timestamps, source revision/modified flag, measured step duration and PASS/FAIL |
| `report.md` | Summary table suitable as an appendix; interpret the stated test mode |
| `case-*.json` | Complete case/audit exports using UUID-based filenames |
| `state/aicm.sqlite3` | Local demonstration database; inspect through `ai_rdr_case.py --database ...` |
| `simulated-host.json` | Host model's final firewall/process/account state (weekly simulations only) |
| `backup.sqlite3` / `receiver.sqlite3` | Week 3 backup / week 4 local receiver, where applicable |

Use `--output /path/to/a/new/folder` for your own destination. Existing folders are
refused. `--non-interactive` runs the same checks without Enter prompts for repeatable
verification; interactive runs are recommended for screenshots. A failed run is
retained as evidence, not overwritten with a later PASS.

The default `artifacts/` directory is ignored by Git. If choosing a custom path
inside the checkout, add an appropriate ignore rule before saving private notes.
The tool itself does not add secrets or collect your
real environment/configuration. Copy selected evidence into your report manually.
Results record the current commit and whether working files were modified. Re-run
after pulling the final commit if you need evidence tied to that exact revision.

## Report worksheet

For each milestone fill in:

```text
Actual date/time:
Commit SHA and modified flag:
Milestone / feature:
Mode: simulated host / real disposable Linux child / live VM integration
Command executed:
Expected outcome:
Observed output and PASS/FAIL:
Screenshot and artifact paths:
Limitation or unresolved integration:
```

Suggested evidence allocation is Week 1 playbooks, Week 2 staged response, Week 3
AICM, Week 4 policy/reliability checks. Use actual dates and development records
for the weekly narrative; these labels do not create historical evidence.

Live Wazuh routing, the central Flask backend, scoped SSH execution, real IPv4/IPv6
traffic tests, account-login enforcement and end-to-end <1 s/<10 s targets remain
separate Ubuntu integration checks. Do not mark them passed from these outputs.
