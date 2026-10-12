# AI-RDR AICM — implementation and usage

This is an original standard-library Python implementation of the patterns in
[the research](aicm-research.md). No TheHive/IRIS/Elastic code was copied.
It requires Python 3.10+ and SQLite; ARM's account response still targets 3.10–3.12.

## What is available

- Incident case creation, assignment, severity, lifecycle, disposition and closure.
- Multiple alerts/evidence references/process and resource operations per case.
- Per-case audit sequence, event/operation/request IDs, actor and reason, redacted
  field changes, source and recording timestamps.
- Atomic case-edit/audit and ARM-state/operation/audit commits. State intents and
  verified effects remain separate because OS commands cannot join SQLite transactions.
- SQL triggers prohibiting audit updates/deletes through normal connections.
- An outbox with explicit acknowledgements and idempotent trusted-event ingestion.
- CLI case inspection, paginated audit timeline, notes, JSON export and safe backup.
- One-time migration of existing `state.json` snapshots; old files are retained.

The database is `/var/lib/ai-rdr/aicm.sqlite3` by default. ARM uses `<state_dir>/aicm.sqlite3`.
The case CLI must be pointed at that same file when `state_dir` is customised.
Journal mode is WAL, sync is FULL, foreign keys are enabled, and writes use
BEGIN IMMEDIATE with a five-second busy timeout. Schema version is recorded in
`PRAGMA user_version`; unsupported versions fail closed.

## Try case management without system actions

From `/workspace/321proj`, use a database outside the checkout:

```bash
python3 ai_rdr_case.py --database /tmp/ai-rdr-demo.sqlite3 create --case-id CASE-DEMO --title "Suspected ransomware"
python3 ai_rdr_case.py --database /tmp/ai-rdr-demo.sqlite3 update CASE-DEMO --version 1 --lifecycle investigating --assignee analyst-5 --reason "Started investigation"
python3 ai_rdr_case.py --database /tmp/ai-rdr-demo.sqlite3 note CASE-DEMO --text "Checking backup activity against detector evidence"
python3 ai_rdr_case.py --database /tmp/ai-rdr-demo.sqlite3 show CASE-DEMO
python3 ai_rdr_case.py --database /tmp/ai-rdr-demo.sqlite3 timeline CASE-DEMO
python3 ai_rdr_case.py --database /tmp/ai-rdr-demo.sqlite3 export CASE-DEMO
```

Repeat the demo in a fresh database or choose a new Case ID; creation deliberately
rejects duplicate IDs. Updates require the current case `version` to prevent one
analyst silently overwriting another. Audit additions update the sequence but do
not change this editable-case version. Rejected version/transitions are audited.

Lifecycle is `open -> investigating -> resolved -> closed`; `open -> resolved`
is also supported. Resolved/closed cases can reopen to investigating with a reason.
Disposition is independent: undetermined, malicious, benign or duplicate. A case
can close as undetermined if its reason explicitly records an inconclusive result.
Duplicate disposition requires an existing canonical `duplicate_of` case and does
not delete either history or rewrite ARM resource ownership.

Closure is refused while any response operation is active or a reversible resource
lease remains applied. Resolve/undo those actions explicitly first. Closure never
unlocks an account, resumes a process or removes a firewall rule as a side effect.
Thaw and kill do not set the incident verdict. New response mutations against a
closed case are refused until it is reopened.

## Wazuh and ARM integration

Deploy the new `ai_rdr_*.py` files together with `freeze_verify_manager.py` using
the README's installation command. It includes the AICM module and case CLI.
Restart the worker after updating code. Set root-only file permissions and the
endpoint's real `agent_id` in `/etc/ai-rdr/config.json`.

The existing response wrappers now:

1. Validate the Wazuh command and complete the check-keys exchange.
2. Attach the original alert by producer + agent ID + alert ID; identical retries
   create no duplicate alert association. Reusing an ID for changed content fails.
3. Create a case if needed and attach attributed evidence references.
4. Record the response request, then commit each operation/state transition and
   its audit event before/after execution as appropriate.
5. Leave the incident lifecycle/disposition for the case-management policy/analyst.

Recommended alert envelope:

```json
{
  "command": "add",
  "parameters": {
    "alert": {
      "id": "wazuh-alert-123",
      "timestamp": "2026-10-12T08:00:00Z",
      "agent": {"id": "001"},
      "rule": {"id": "100100", "level": 12},
      "data": {
        "case_id": "CASE-001",
        "pid": 4128,
        "start_ticks": 123456,
        "boot_id": "endpoint-boot-uuid",
        "risk_score": 0.75,
        "model_version": "rf-lab-v1"
      }
    }
  }
}
```

If `case_id` is absent, immutable process identity produces the same Case UUID
across that process's alerts. Without complete process identity, the source alert
ID produces the case key. A host/time window alone never merges incidents.
Independent roots need an explicit shared Case ID from the detector/integration
contract. Correlation does not infer that two unrelated processes are ransomware.

Process operation IDs include case, agent, PID, start ticks and boot ID. Identical
retries reuse the operation; a second root under the same case gets another ID.
Use `--operation <id>` with approval/thaw when multiple roots are active. Firewall
and account leases keep incident ownership: process thaw still does not remove them.

Service audits identify the configured ARM endpoint. Local analyst CLI commands
identify the executing Unix UID. With sudo this is normally root; this is honest
local process attribution, not authenticated identification of the human analyst.
M6 must supply human identity from its authenticated session when calling the
Python API. Alert JSON never selects an analyst actor.

## Migration and failure recovery

Stop the old worker before deployment. Use a VM snapshot/backup before changing
the running endpoint. On the first ARM transaction:

- If SQLite has no ARM snapshot, read existing `state.json`, then commit its
  snapshot, case/operation projections and transition audit atomically.
- Keep the original JSON file; it stops being authoritative once migration commits.
- Preserve legacy one-root operation and case IDs, including lease ownership.
- Fail on corrupt JSON/SQLite; never substitute an empty state or silently revert
  to a stale JSON archive.

Existing JSONL audit history is preserved on disk but is **not automatically
imported**: it lacks stable IDs/actors and should remain labeled legacy evidence.
The old `audit_log` config field is accepted but is no longer written. New history
is in SQLite, inspectable/exportable with the case CLI. Do not run old and new
workers against the same endpoint simultaneously.

Disk failure before intent commit prevents a new unjournaled mutation. Failure
after an OS effect leaves the persisted intent for the existing recovery worker;
the exact effect time may remain unknown. The store does not pretend SQLite makes
OS signals/firewall changes atomic. Migration history describes imported state,
not a reconstruction of the original action timestamps.

## Python boundary for M6

```python
from ai_rdr_aicm import CaseStore

store = CaseStore("/var/lib/ai-rdr/aicm.sqlite3")
# Construct from the authenticated server context, not client-supplied JSON.
actor = {"type": "user", "id": authenticated_user_id}
case = store.get_case(case_id)
case = store.update_case(case_id, actor=actor, expected_version=case["version"],
                         lifecycle="investigating", reason="Analyst accepted case")
events = store.timeline(case_id, after=0, limit=100)
```

Case management itself does not execute system responses. Use the ARM approval/
thaw/undo boundary for those actions. No unauthenticated HTTP server is added.
M6 owns REST routing, authentication, authorisation and case visibility controls.

An optional transport can call `pending_events(limit)`, deliver each event to a
trusted receiver's `ingest_event(event, received_by=...)`, and then call
`acknowledge([event_id])` only after a durable acknowledgement. A lost network reply
is safe to retry: the receiver checks event ID and content digest. Event IDs and
source occurrence/actor are retained; central sequence/recording time are new,
with origin sequence/time in delivery metadata. Outbox reads preserve per-case
sequence even if a host wall clock moves backwards.

Transport scheduling, TLS authentication and the OpenSearch exporter are **not
implemented**. Ingestion imports audit history only: it does not automatically
synchronise central case fields, alert/evidence tables, operation projections, or
ARM state. The complete case export is available for M6 to design that separate
projection contract. Never send central imported history back into the endpoint
route, or replay historical events as OS commands.

## Backup, audit protection and limits

```bash
sudo python3 /var/ossec/active-response/bin/ai_rdr_case.py backup /tmp/aicm-backup.sqlite3
sudo python3 /var/ossec/active-response/bin/ai_rdr_case.py timeline -
```

`backup` uses SQLite's backup API and refuses to overwrite an existing destination.
Copying only a live main database file can miss WAL commits. `timeline -` displays
case-independent security events, including malformed response requests. Pending
delivery acknowledgements never delete the original audit events. Case timelines
are paginated; JSON export includes the full case record and history.

The append-only API and SQL triggers protect against ordinary accidental edits;
root can still alter/drop the database or triggers. There is no hash chain or
external integrity checkpoint. Secret-named metadata fields are recursively
redacted, but arbitrary free text is not a secret detector: never submit secrets
in descriptions, notes or reasons. Raw evidence bytes are not stored here.

SQLite is suitable for the single-host prototype. Do not share its file over a
network filesystem. A large response tree makes several durable writes and may
increase containment latency; the design's sub-second/ten-second end-to-end goals
remain unverified. Cases/audit/outbox currently have no automatic retention, event
merging, archival pruning, tenant isolation or multi-server database support.

Run all tests with `python3 -m unittest discover -s tests -v`. AICM tests exercise
transaction rollback, concurrent event sequencing, duplicate delivery, audit
immutability, backup/restore, correlation, legacy migration and ARM integration.
