# AICM case records and audit trail: research and proposed design

Research date: 12 October 2026. Scope: the M5 component in `321proj`.
This document is a design proposal; it does not implement or deploy AICM.
The subsequent implementation and its supported boundaries are described in
[AICM usage](aicm-usage.md). The gap analysis below records the pre-AICM baseline.

## Evidence and scope

The supplied project document assigns M5 the case state machine that maps alerts
to a Case ID, response/undo operations, and case objects handed to M6. M6 owns the
dashboard, REST API, case timeline, and integration contract. It does not specify
a database, a complete case schema, audit integrity guarantees, or retention limits.

I inspected primary source code from TheHive, DFIR-IRIS, Elastic Kibana Cases, and
the Elastic Common Schema (ECS). Official documentation sites were inaccessible
from this environment (proxy HTTP 403); GitHub source access worked. The findings
below describe the inspected revisions, not features verified in running products.
No third-party implementation code was copied into the project.

| Reference | Inspected version | What the source establishes |
|---|---|---|
| TheHive | Archived public code, commit `d390a0316ccd7780df6a49eccc773e5c28b43cc2` | Case lifecycle, resolution and impact are different fields; audit objects link requests, users and target objects |
| DFIR-IRIS | Stable tag `v2.4.29`, commit `f551ab8de1f0cbc296d2930ef26e4ae1cb2425e8` | Separate case, alert, timeline-event, asset and user-activity records; relational alert/case association |
| Elastic Cases | Development snapshot, commit `ad65a885d98834829ef1967ff0bc9b33bda7c84d` | Typed case fields and user actions; separate authorization audit and persisted-action audit code |
| ECS | Commit `9868ff5b9cab65376fab3e3829382b3424a3ee69` | Event action/outcome, timestamps, sequence and duration conventions |

TheHive's repository README says its public v3/v4 distribution is retired. Its
models are a historical architecture example, not a recommendation to install
those versions or a description of current TheHive commercial capabilities. IRIS's
current master identifies a v3 beta, so the comparison deliberately uses v2.4.29.
Elastic's snapshot is not a promise that every field exists in your installed release.

## 1. TheHive: case, disposition, impact and audit are separate

The inspected `Case.scala` defines case statuses `Open`, `Resolved`, `Duplicated`.
It separately defines resolution values including `Indeterminate`, `FalsePositive`
and `TruePositive`, and impact values including `NoImpact` and `WithImpact`.
Case metadata includes title, description, severity, assignee, tags, start/end
dates, organisation and created/updated metadata. [H1]

`Audit.scala` defines request ID, action, main-action flag, target object ID/type,
and details. Audit objects link to users and context. Action labels include create,
update, delete and merge. [H2]

Illustrative projection of those fields, not an exact API response:

```json
{
  "title": "Suspected ransomware on endpoint-01",
  "status": "Resolved",
  "resolutionStatus": "FalsePositive",
  "impactStatus": "NoImpact",
  "summary": "Backup workload; suspended process resumed"
}
```

**Lesson for AI-RDR:** `THAWED` is a response result, not a case verdict. An
inconclusive-timeout thaw must not become a false-positive disposition. Likewise,
`KILLED` does not mean the investigation is closed or there was no file damage.
Include request correlation and target identity in audit records.

## 2. DFIR-IRIS: alerts, evidence timeline and user activity

IRIS `Cases` stores a numeric ID, UUID, name/description, owner, status, severity,
classification, review information, opening/closing dates and closing note. The
model also has modification history. [I1]

`AlertCaseAssociation` relates alert IDs and case IDs; the schema permits multiple
alerts per case and an alert associated with multiple cases. Alerts retain source,
source reference/content, severity, classification and resolution. [I2]

`CasesEvent` stores an incident event's date separately from its added date, source,
content/raw content, author, parent event and modification history. `UserActivity`
separately records actor, case, activity date/description and whether the action
came from the API or user input. [I1, I3]

Illustrative relational example using the inspected field names:

```text
cases:                 case_id=17, owner_id=5, name="Endpoint encryption"
alerts:                alert_id=81, alert_source="Wazuh", alert_source_ref="alert-81"
alert_case_association: alert_id=81, case_id=17
cases_events:          case_id=17, event_title="Decoy modified",
                       event_date=<source time>, event_added=<recording time>
user_activity:         case_id=17, user_id=5,
                       activity_desc="Approved containment", is_from_api=true
```

**Lesson for AI-RDR:** link alerts to a case instead of replacing the previous
alert. Distinguish the forensic timeline (what happened on an endpoint) from the
audit trail (what the system or analyst did). Preserve both occurrence and receipt
times, so a delayed alert does not appear to have happened when it was ingested.
The inspected modification-history fields are not evidence of cryptographic
immutability; they should not be described as tamper-proof.

## 3. Elastic Cases: typed user actions and authorization audit

The case type has `open`, `in-progress`, `closed`, severity, assignees, tags,
observables, created/updated/closed actors and times, version, alert totals, and
optional acknowledgement/investigation/resolution timing fields. Close reason is
a separate field. Here `owner` identifies the owning plugin, not the assigned
analyst. [E1]

User actions have timestamps, actors, an action verb and a typed payload: status,
severity, assignment, comment, create/delete case and other supported changes.
An illustrative status-change record using those fields is: [E2, E3]

```json
{
  "created_at": "2026-10-12T08:00:00Z",
  "created_by": {"username": "analyst-5"},
  "owner": "securitySolution",
  "action": "update",
  "type": "status",
  "payload": {"status": "in-progress"}
}
```

This is a shortened example, not a full API response. The inspected authorization
logger uses failure for rejected access, unknown for an authorized write that is
not yet known to have completed, and success for a successful read. A separate
user-action logger records successful stored actions. [E4, E5]

**Lesson for AI-RDR:** a requested or authorized action must not be reported as
an effective action. Record requested, rejected, started, completed, failed and
reconciled phases with explicit outcomes. Also audit denied approvals and invalid
state transitions, not only successful containment.

## 4. What ECS contributes

ECS defines `event.action`; `event.outcome` with success/failure/unknown; sequence
numbers; source occurrence, first-observed and central-ingestion timestamps; and
`event.duration` in nanoseconds. [S1]

Use these semantics for searchable OpenSearch exports. Keep detailed states such
as PARTIAL in an AI-RDR-specific result field; do not put PARTIAL into ECS outcome.
For example, an incomplete required action can have `outcome=failure` and
`result=partial`. A detected malicious event is not itself a failed response.
Sequence establishes ordering within a defined producer/case stream; it is not a
global causal order across unsynchronised hosts.

## Gaps in the pre-AICM implementation

The existing `state.json` is an endpoint response journal. Its `cases` map is bound
to one process root per Case ID. It has no general incident title, assignment,
alert collection, evidence references, verdict, closure reason or merge relation.
Block/isolate/disable can create resource leases without creating a case record.

`Runtime.audit()` appends timestamp, case/action/status and details to JSONL. It
does not include stable event/request IDs, per-case sequence, authenticated analyst
identity, source versus ingestion time, policy/model version or consistent before/
after values. Entry-point rejection paths are primarily stderr messages.

State writes are fsynced; audit append is not fsynced. State and audit live in
separate files, so a crash can leave a state change without a matching audit event.
Current root approval records a reason but does not establish who the human
analyst was. These are limitations to fix in AICM, not a claim that the existing
response tests cover an audit database.

## Recommended AICM model

Use one incident case with multiple alerts, endpoints, evidence references and
response operations. Separate these three state dimensions:

| Dimension | Proposed values | Owner |
|---|---|---|
| Investigation lifecycle | open, investigating, resolved, closed | AICM/authorised analyst |
| Disposition | undetermined, malicious, benign, duplicate | AICM/authorised verdict policy |
| Each response operation | preparing, frozen, review, containing, killed, thawed, failed | ARM endpoint workflow |

Closing requires a recorded reason and an explicit decision about remaining
response leases. It should not silently remove isolation. Reopening is a new audit
event. A duplicate case retains its history and points to a canonical case.

Proposed tables/collections:

- `cases`: UUID, display reference, title, severity, lifecycle, disposition,
  assigned analyst, creation/update/closure times, closure reason, version.
- `case_alerts`: original producer/agent/alert IDs, correlation metadata, source
  occurrence and receipt times, score, detector/model version, payload reference.
- `case_assets`: agent identity, host identity and relevant account/network targets.
- `evidence`: type, producing component, external reference, content digest, size,
  capture time and endpoint/process identity. A digest detects changed bytes; it
  does not prove the evidence is truthful or was lawfully collected.
- `response_operations`: unique operation ID, Case ID, endpoint, immutable process
  identity or other target, policy/version, reason, current state and undo capability.
- `audit_events`: unique event ID, sequence, actor, request/operation IDs, event
  type, phase, outcome, target, reason, redacted changes, times and duration.
- `outbox`: pending delivery of committed endpoint/central events; retry/ack metadata.

Start with SQLite for a single-host bachelor prototype. Use foreign keys, short
transactions, busy timeouts, schema migrations, local disk and durable sync. WAL
can improve reader/writer coexistence but still allows only one writer. Do not
share a SQLite file over network storage. Move the central database to PostgreSQL
if M6's deployment requires several API writers or multiple machines.

### Example proposed AI-RDR audit event

```json
{
  "schema_version": 1,
  "event_id": "22222222-2222-4222-8222-222222222222",
  "case_id": "11111111-1111-4111-8111-111111111111",
  "case_sequence": 12,
  "operation_id": "33333333-3333-4333-8333-333333333333",
  "request_id": "approval-request-7",
  "event_type": "response.freeze",
  "phase": "completed",
  "outcome": "success",
  "actor": {"type": "service", "id": "arm:endpoint-01"},
  "target": {
    "agent_id": "001",
    "pid": 4128,
    "start_ticks": 123456,
    "boot_id": "endpoint-boot-uuid"
  },
  "reason": "candidate behavioural score",
  "policy_version": "freeze-policy-v1",
  "changes": {"response_state": {"before": "preparing", "after": "frozen"}},
  "occurred_at": "2026-10-12T08:00:00.100Z",
  "recorded_at": "2026-10-12T08:00:00.105Z",
  "duration_ns": 5000000
}
```

Example values above are invented for illustration, not measured results.
Store timestamps in UTC and let M6 render the viewer's timezone. Duration uses a
monotonic clock within one boot, not subtraction of wall clocks on different hosts.
Keep risk score and reason, but never passwords, tokens or full shadow entries.

## Integration, correlation and failure recovery

AICM belongs alongside the central application; ARM remains on endpoints. M5 owns
case creation/correlation and case/action schemas; M6 exposes the authenticated
API and UI. M1/M2/M3 supply stable alert/evidence and endpoint identities.

On the normal route, AICM supplies a Case ID before dispatch. For a local decoy
fast path, the endpoint can mint an origin Case UUID and persist it without waiting
for a central call. AICM subsequently adopts it or records an alias after correlation.
Keep the origin ownership ID stable on endpoints: changing central grouping must
not accidentally revoke firewall/account leases held under the original ID.

Deduplicate by producer/agent/source-event ID with a database uniqueness constraint,
not only by timestamps. Correlate an active response using agent ID, boot ID and
process start ticks. Link descendants through observed lineage. Host/time-window
similarity can suggest a merge but should not automatically combine unrelated
incidents. Each response gets its own operation ID, so several roots can belong
to one case without overwriting each other's workflow state.

For a case edit, commit the case update, audit event and delivery outbox entry in
one database transaction. For an OS action:

1. Commit a requested operation plus its audit event locally.
2. Execute the OS action outside the database transaction.
3. Verify the effect; commit the result plus audit event/outbox entry.
4. After a crash, reconcile outstanding operations against actual OS state. Record
   observed/reconciled outcomes; do not invent an exact time for an unobserved effect.

SQLite and an OS signal/firewall command cannot be one atomic transaction. The
intent/result pattern makes that gap explicit. Audit insertion failure should
prevent an unjournaled new mutation; disk failure after an effect must be surfaced
and reconciled. Retrying delivery uses stable event IDs and idempotent central
ingestion. Local acknowledgements can be retried if the central commit succeeded
but its network reply was lost.

OpenSearch receives an asynchronous, searchable projection. It should not be the
sole transactional authority for case changes. A dashboard outage or remote-index
failure must not block the decoy containment path. A UI timeline can combine
evidence and audit events while visibly labeling their different kinds.

## Integrity, access and retention

Make audit entries append-only through the application API; corrections create new
entries referencing old ones. Authorise operations by role and log the identity
from the authenticated session, not a client-supplied username. Record denied
requests in a security audit stream without exposing inaccessible case details.

Database permissions, backups and optional append-only triggers reduce accidental
rewrites but cannot defeat a compromised administrator. An optional hash chain
with externally stored signed checkpoints can help detect rewriting/truncation;
a chain stored beside the log cannot prove that a root attacker did not replace
both. This is a proposed enhancement, not an integrity feature established by
the compared products' model files.

Set retention and export rules deliberately; the project has no fixed retention
requirement. Keep case/audit records and large raw evidence under separate policies.
Do not purge unresolved cases, active resource ownership or undelivered outbox
events. Record export/deletion actions and test backup restoration.

## Evaluation and implementation order

Measure duplicate suppression, missing/conflicting event counts, invalid-transition
rejection, actor attribution, restart recovery, delivery backlog, audit append and
timeline-query p50/p95/p99, and local audit overhead added to containment latency.
There is no source-backed universal AICM latency limit. Benchmark against the
project's existing `<1 s` decoy and `<10 s` behavioural end-to-end budgets.

For initial lab stress tests, try 1, 10 and 100 events/second for 60 seconds, plus
simultaneous updates to the same case, then inspect every expected event/sequence.
These loads are proposed experiment settings, not capacity claims. Add crash tests
before/after intent, effect, result commit and central acknowledgement; disk-full,
malformed input, duplicate delivery and index-unavailable tests should preserve
known state and report uncertainty explicitly.

Build in this order:

1. Versioned schemas, SQLite case/audit storage and unique ingestion keys.
2. Case lifecycle/disposition, alert association and independent operation IDs.
3. ARM intent/result integration, endpoint outbox and recovery.
4. M6 authenticated case/timeline APIs and OpenSearch projection.
5. Export, retention, backup restoration and optional integrity checkpoints.

Do not expand this into a full SOAR product: assignments, reasons, references,
response results and a reliable timeline are sufficient for the first M5 milestone.

## Primary sources

- [H1: TheHive case model](https://github.com/TheHive-Project/TheHive/blob/d390a0316ccd7780df6a49eccc773e5c28b43cc2/thehive/app/org/thp/thehive/models/Case.scala)
- [H2: TheHive audit model](https://github.com/TheHive-Project/TheHive/blob/d390a0316ccd7780df6a49eccc773e5c28b43cc2/thehive/app/org/thp/thehive/models/Audit.scala)
- [H3: TheHive distribution notice](https://github.com/TheHive-Project/TheHive/blob/d390a0316ccd7780df6a49eccc773e5c28b43cc2/README.md)
- [I1: IRIS cases and timeline events](https://github.com/dfir-iris/iris-web/blob/f551ab8de1f0cbc296d2930ef26e4ae1cb2425e8/source/app/models/cases.py)
- [I2: IRIS alerts and case association](https://github.com/dfir-iris/iris-web/blob/f551ab8de1f0cbc296d2930ef26e4ae1cb2425e8/source/app/models/alerts.py)
- [I3: IRIS user activity and related models](https://github.com/dfir-iris/iris-web/blob/f551ab8de1f0cbc296d2930ef26e4ae1cb2425e8/source/app/models/models.py)
- [I4: IRIS version guidance](https://github.com/dfir-iris/iris-web/blob/37c5521ac009bd018a2fac7bc01d70735d130c6c/README.md)
- [E1: Elastic case schema](https://github.com/elastic/kibana/blob/ad65a885d98834829ef1967ff0bc9b33bda7c84d/x-pack/platform/plugins/shared/cases/common/types/domain/case/v1.ts)
- [E2: Elastic user-action schema](https://github.com/elastic/kibana/blob/ad65a885d98834829ef1967ff0bc9b33bda7c84d/x-pack/platform/plugins/shared/cases/common/types/domain/user_action/v1.ts)
- [E3: Elastic status-change payload](https://github.com/elastic/kibana/blob/ad65a885d98834829ef1967ff0bc9b33bda7c84d/x-pack/platform/plugins/shared/cases/common/types/domain/user_action/status/v1.ts)
- [E4: Elastic authorization audit](https://github.com/elastic/kibana/blob/ad65a885d98834829ef1967ff0bc9b33bda7c84d/x-pack/platform/plugins/shared/cases/server/authorization/audit_logger.ts)
- [E5: Elastic persisted user-action audit](https://github.com/elastic/kibana/blob/ad65a885d98834829ef1967ff0bc9b33bda7c84d/x-pack/platform/plugins/shared/cases/server/services/user_actions/audit_logger.ts)
- [S1: ECS event semantics](https://github.com/elastic/ecs/blob/9868ff5b9cab65376fab3e3829382b3424a3ee69/schemas/event.yml)
