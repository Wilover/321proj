# M5 compatibility review — uploaded AI-RDR project

Reviewed: 16 October 2026. Input: `AI-RDR-main.zip` and the updated architecture.
This is a source review, not live validation of the three VMs. No Ansible playbook,
SSH connection, live HTTP request, firewall action or account change was performed.

Subsequent M5-only changes fix the alert-only gap, add controller-scoped IPv4/IPv6
SSH exceptions, make additional process approval configurable, and add manual
demonstrations. The findings below describe the uploaded snapshot **before** those
changes. Central HTTP/SSH transport, provisioning and case projection still need
integration; see [manual testing](manual-four-week-tests.md) for the current scope.

## Policy baseline from the user

Automatic containment from attributed decoy evidence is the primary response path.
Manual approval is an additional safeguard, not an unconditional prerequisite for
every decoy incident. The uploaded architecture's approval-only description is not
the desired policy baseline. Keep explicit approval available for critical assets,
uncertain attribution and analyst overrides.

The M2 package's separate `response_mode=alert_only` contract applies to ML-only
signals. It should not suppress an independently verified decoy fast path, but
should prevent autonomous ML-only freeze/kill/isolation while that contract is active.

## What is actually included

- All 13 files in `m5/` match the corresponding files in `321proj` byte for byte:
  eleven Python files, the worker unit and the Wazuh XML template.
- The ZIP includes M2 code/contracts, M3 checkpoint code, Ansible provisioning and
  architecture documentation.
- It does not include `backend/app.py`, `backend/arm.py`,
  `backend/host_controller.py`, `backend/irdp/`, or the backend's AICM implementation.
  `setup_airdr_detect.yml` clones those from a separate, placeholder Git remote and
  runs `python -m backend.app` from `/opt/airdr-detect`.
- It omits M5's configuration example, tests and deployment documentation. The
  included Ansible files do not install the M5 modules, `/etc/ai-rdr/config.json`
  or `ai-rdr-worker.service`.

The VMs being online does not establish that the archive contains their running
application source. The full backend integration cannot be verified until that
source is available. The playbook's expected source location is a lead to check,
not evidence that the deployed files/version match it.

## Compatibility findings

### 1. Two response entry points exist; choose one coordinator

The provisioned path is:

```text
Wazuh manager container -> arm-trigger.py -> POST /api/arm/trigger
                       -> central backend -> SSH -> target
```

M5's current entry point is:

```text
Wazuh endpoint executable -> newline JSON/check_keys -> local root action
```

They are different interfaces. Importing the local Runtime into Flask would not
make operations remote: `/proc`, signals, firewall and account commands act on the
machine running Runtime. Do not send a target PID to a local controller process.

The old M5 XML template also conflicts with the current manager hook: rule 100100
selects freeze in the template, while 100100/100103 select honey-file HTTP triggers
in provisioning; 100103 selects IP blocking in the M5 template. Installing both
routes can produce duplicate/inconsistent responses. Do not merge the template
unchanged into the Docker manager configuration.

### 2. The payload does not satisfy M5's process contract

The embedded manager hook emits `host`, `honeyfile_triggered`, `signals`,
`trigger_timestamp`, `wazuh_alert_id`, optional `process_id` and `file_path`.
It drops `agent.id` and does not supply process boot ID/start ticks or attributed
evidence. It is a central trigger object, not M5's Wazuh envelope.

Required adapter work:

| Existing field | M5/common contract requirement |
|---|---|
| `host` IP | Resolve to a trusted enrolled agent/allowed target; retain agent ID |
| `wazuh_alert_id` | Stable source event ID for deduplication and correlation |
| `trigger_timestamp` | Preserve as source occurrence time |
| `process_id` | Canonical integer PID plus event-time start ticks and boot ID |
| `honeyfile_triggered=true` | Evidence identifying a registered decoy, actual operation and attributed process where available |
| `file_path` | Normalised absolute path, consistent with the decoy registry |

PID alone can be reused. Do not look up the current process and claim its start
ticks were captured at the original event time. If process attribution is missing,
a host-specific isolation decision and a process-specific kill decision need
different eligibility rules. Do not invent a PID identity to enable kill.

The hook prefers `audit.file.name` even if it is just a basename; it does not join
that with `audit.directory.name`. A mocked alert containing both produced only
`decoy.xlsx`, not `/srv/finance/decoy.xlsx`.

### 3. Decoy policy is partly compatible, but evidence is not wired

M5 `Workflow.confirmed` already accepts an attributed `decoy_write` without analyst
approval on a noncritical endpoint. The independent isolation action can also be
selected directly. This supports the user's primary automatic-response approach.

However, the current hook sets a boolean for a matched rule; it does not construct
that evidence. M3's registry provides exact-path matching, but its checkpoint
watcher prints alerts for ACCESS/CLOSE_WRITE and supplies no external M5 event or
process identity contract. The Ansible auditd route is distinct from this watcher.
Unify the evidence contract; do not label a read/access event as `decoy_write`
merely to pass the current verifier.

The hook comments describe PB-04 as always pending approval. Backend code is not
present, so the actual gate cannot be inspected. Adapt it to explicit automatic/
approval policy after reviewing the real implementation, rather than removing all
approval checks or assuming the comment describes the running version.

### 4. M5 currently ignores M2's alert-only mode

M2 `inference.py` returns `response_mode="alert_only"`, and its contract explicitly
disables automatic response from that path. M5 does not inspect the flag.

Reproduction with a fake Runtime: a valid process alert with score 0.75 and
`response_mode="alert_only"` produced a FROZEN operation and one mocked SIGSTOP.
No real signal was sent. Add a decision boundary before mutations; record the
ML-only alert/case while alert-only is active. An independent attributed decoy can
still authorise response under its own policy.

Do not equate M2's model-specific probability threshold with M5's candidate
0.60–0.90 range or a Risk Fusion risk tier. Agree score meaning and policy version.

### 5. SSH privilege and isolation contracts differ

The provisioned `arm-executor` sudoers supports selected `iptables` commands using
`airdr_isolate`, `kill -9`, file quarantine/lock and backup commands. It does not
authorise our wrappers, pidfd operations, SIGSTOP/SIGCONT, account expiry/locking,
`ip6tables`, or our `iptables -w 1` commands and chain names.

The central service runs as a nonroot user; our response entry points require root.
Simply copying Python files into `/opt/airdr-detect` will not connect these contracts.
Do not fix this with unrestricted `sudo python3` or a general root shell. A suitable
bridge is a root-owned target helper with validated structured inputs, approved
operations and target identity checks, called by the dedicated SSH executor.

Current M5 isolation drops SSH. The provisioned bridge preserves SSH with an
IPv4 INPUT-chain rule, while our playbook covers IPv4/IPv6 INPUT and OUTPUT and
preserves manager TCP traffic. Merge the intended management exceptions explicitly:
controller-to-target SSH from the detection host, target-to-manager Wazuh traffic,
and loopback, with both address families handled. A remote isolate must not remove
the only channel used for its undo.

The sudoers template's command-name restrictions are not the same as validating
dynamic targets; for example `kill -9 *` is broad. New helper operations need
bounded target validation, not only additional wildcard rules.

### 6. AICM needs an explicit central projection/storage boundary

M5 currently stores cases, response state, audit and outbox in endpoint SQLite.
Provisioning describes central OpenSearch action state and has separate mappings
for `ai-rdr-response-audit-*` and `ai-rdr-incident-cases-*`.

The included M5 `ingest_event` imports history only. In a mocked integration test,
all endpoint events were ingested into a second store; its case had a timeline but
zero alert and operation records. Copying that method into Flask is not complete
case synchronisation.

Choose one authoritative central case implementation after inspecting the backend.
Keep local durable execution intent/result records for recovery and offline
delivery. Map central display fields deliberately:

- `lifecycle` / `disposition` to the agreed case state/verdict fields;
- `assignee` to case owner (not the service actor);
- `operation_id` to action ID and `event_id` to each unique audit document ID;
- typed targets to the mapped `target_entity` representation;
- actor, reason, phase, result and timestamps to explicit audit fields;
- PB-01..04 IDs to operation records, without treating each action as a new case.

Never use action ID alone as the audit document ID: multiple phases of one action
would overwrite history. Ranked recommendations are described by the architecture
but are not implemented by our M5 CaseStore. Keep case closure separate from
thaw/kill and from release of network/account leases.

### 7. Delivery and automatic-trigger trust require attention

The embedded hook POSTs over HTTP with Content-Type only; it does not send an
authentication header or persist a retry queue. A mocked connection failure was
logged, then returned exit code 0. Thus this hook alone does not guarantee eventual
trigger delivery. The backend's authentication/network controls are not inspectable
from this ZIP; this finding is not a claim that the running service is unauthenticated.

For the automatic decoy path, authenticate the producer, validate allowed target
identity and retain original evidence. Add bounded durable delivery/reconciliation
with stable event IDs so a network retry does not repeat a kill or release another
case's isolation. Keep ML inference, external intelligence and human waiting out
of the fast-path timing budget when the decoy policy already authorises containment.

## Recommended integration order

1. Obtain the actual central backend source/version from the detection VM; inspect
   its routes, policy gates, host controller, action store and AICM implementation.
2. Define one trigger/evidence/operation contract and explicit decoy-auto versus
   ML-alert-only policy. Preserve approval as a configurable additional safeguard.
3. Adapt the existing central controller to one validated target-side execution
   boundary; retain the required SSH/Wazuh management exceptions.
4. Deploy M5 helpers/config/worker through Ansible, rather than maintaining manual
   file copies alongside a separate orchestration route.
5. Connect intent/result audits and case projections using stable IDs; test restart,
   duplicate delivery, undo ownership and a disconnected central backend.
6. Validate end-to-end latency and damage on benign lab simulations before claiming
   the decoy <1 s target. A 10 s HTTP timeout is a failure wait, not a readiness SLA.

The recommended split is central policy/correlation/case presentation on
`airdr-detect`, bounded action execution and recovery on `airdr-target`, and Wazuh
telemetry/trigger forwarding on `airdr-siem`. Do not run two independent automatic
orchestrators against the same event.

## Review evidence and limitations

Verified here: 13 matching M5 files; missing backend source/deployment wiring;
mocked manager-hook payload and outage behaviour; ignored ML alert-only flag;
audit ingestion not populating case projections. Mocked tests used no live network
or real host actions. Ansible and third-party model training were not executed.
The three VMs and any claimed live PB-01..04 behaviour were not independently tested.
No production source or configuration was changed by this review.

Primary source locations within the upload:

- `ansible/playbooks/ubuntu/setup_airdr_detect.yml`: backend repo and service.
- `ansible/playbooks/ubuntu/setup_airdr_arm_active_response.yml`: trigger payload,
  manager-container placement and HTTP forwarding.
- `ansible/playbooks/ubuntu/setup_airdr_arm_executor.yml`: target sudoers commands.
- `ansible/playbooks/ubuntu/setup_airdr_index_mappings.yml`: action/audit/case mappings.
- `m2/docs/M2_API_CONTRACT.md`, `m2/src/m2_pipeline/inference.py`: alert-only mode.
- `m3/decoy_registry.py`, `m3/m3_checkpoint2.py`: registry and checkpoint event scope.
- `m5/ai_rdr_response.py`, `m5/freeze_verify_manager.py`, `m5/ai_rdr_actions.py`:
  endpoint response contract and policy.
- `m5/ai_rdr_aicm.py`: local persistence and history-only event ingestion.
