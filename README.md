# AI-RDR M5

M5 contains the Risk Matrix, endpoint response playbooks (isolate, kill, block IP,
disable account), the freeze → verify → contain/thaw workflow, and AICM case
records with a SQLite audit trail and an authenticated M6 gateway. Keep the
fifteen runtime Python files together because they share imports.

Use Ubuntu 22.04/24.04 with Python 3.10–3.12. The worker and signed SSH gateway
run independently of Wazuh. No pip dependencies are required. Windows VS Code can
connect to the Ubuntu VM through Remote SSH.

Run from the project root without sudo:

```bash
python3 -m unittest discover -s tests -v
python3 tests/manual_m5.py playbooks
python3 tests/manual_m5.py freeze
python3 tests/manual_m5.py aicm
python3 tests/manual_m5.py freeze --real-process
```

The three manual tests pause between steps and save outputs under
`artifacts/manual-m5/`. Firewall and account actions are simulated. The explicit
`--real-process` test signals only disposable child processes it creates; unit
kernel tests also use disposable children. These tests do not validate live
Wazuh dispatch, network connectivity or account login enforcement.

`config/lab.example.json` is an endpoint configuration example for deployment
alongside central ARM. Set the controller addresses, endpoint ID and protected
accounts before use. Both M5 automatic action lists are empty in this profile.
Process alerts require `pid`, `start_ticks` and `boot_id`; decoy evidence must
match that identity.

## Falco and ARM deployment

Falco sends events through Falcosidekick and Kafka. Faust combines live ML and
threat-intelligence evidence and posts detections to ARM. ARM owns live
playbook selection and approvals. Keep `ossec.conf.example` inactive in this
deployment. M5's evaluator and protection policy can still be exercised locally.

If deploying M5's endpoint worker or gateway alongside ARM, install the runtime
under `/opt/ai-rdr/m5/` as described in Endpoint deployment. Leave
`automatic_actions` and `attributed_decoy_actions` empty so ARM is the sole
automatic dispatcher. The signed M5 gateway continues to serve case queries
and analyst actions. Connecting ARM's own playbook execution to M5 requires
an authenticated execution contract between the two.

For M5 isolation, configure `controller_addresses` and `controller_ssh_port`
to preserve SSH and undo access. By default, isolated hosts drop Kafka broker
traffic. If deployment policy calls for continued telemetry during isolation,
add the actual broker IP and TCP port to `telemetry_peers`. Each entry is an
object such as `{"address": "192.0.2.67", "port": 9092}`. M5 allows outbound TCP
to that pair and established replies from it. These exceptions cover host
INPUT/OUTPUT traffic. Traffic forwarded for bridged containers needs its own
deployment verification. `manager_addresses` and `manager_ports` are for
legacy Wazuh profiles.

For an in-place cutover, release active M5 firewall restrictions before
changing the peer list, since installed chains already contain the old rules.
Pause dispatch during the switch, preserve `/etc/ai-rdr/config.json` and
`/var/lib/ai-rdr/`, and restart the worker against the new install path.

### Identification and action permission

M5 computes `target_identified` and `automatic_response_allowed` separately and
records both in `response.policy_evaluated` / `response.policy_blocked` audit
events. It executes only when the target is identified and the action is
permitted. Incoming JSON booleans with these names, or `analyst_approved`, cannot
grant permission. Process identity is checked against the running process again
before containment; matching PID fields alone do not prove a honeyfile operation.

`automatic_actions` defaults to `[]`: a known PID, high score, or an
`automatic` input flag alone does not authorise a new action. Ordinary automatic
requests require **both** an explicit `response_mode: automatic` and the action
in this endpoint allowlist. A nested `ml.response_mode: alert_only` takes
precedence over an outer automatic flag. A PID-free M2/M3 input remains review
evidence; M5 does not guess an actor from host/time proximity.

The independent attributed-decoy policy is separate:
`attributed_decoy_actions` defaults to `["freeze", "kill", "isolate"]`.
Setting it to `[]` disables that automatic path. `require_approval` or
`critical_asset` blocks automatic termination and standalone network/account
restrictions; an independently permitted Freeze may still precede analyst
review. Permission to Freeze is not permission to Kill. Approval is taken only
from local operation state written by the privileged analyst control.

For standalone playbooks, target identity is action-specific: an enrolled host
for isolation, a validated IP for blocking, or a supported local account for
restriction. Identifying these entities does not claim a responsible PID or
grant permission. A policy using attributed-decoy authority also requires the
decoy actor's current process identity. Correct case-owned delete/thaw/undo
remains available when automatic permissions are subsequently disabled.

For an **explicitly authorised disposable lab only**, set
`automatic_actions` to the actions being exercised, for example
`["freeze", "isolate", "block", "disable"]`, and send the explicit automatic
mode. The manual demonstrations and local process-check use their own such lab
configurations. The supplied endpoint example disables both automatic action
lists; the evaluator does not change installed endpoint policy for you.

## Risk Matrix

`ai_rdr_risk.py` implements a deterministic, configurable entity scorer. It is
inspired by Splunk's entity risk contributions and Elastic's entity-risk
aggregation; it does not copy either vendor's implementation. Scores are
priorities on 0–100, **not ransomware probabilities**. The supplied weights,
bands and time windows are prototype policy settings, not calibrated findings.
No additional trained model or pip package is required.

Default bands: below 30 Normal; 30 to below 70 Suspicious; 70–100 High Risk.
Missing/invalid/unavailable evidence alone produces Unknown, not Normal.
The base score is the strongest eligible contribution, plus 20 for each
additional independent group, capped at 100. M1 monitoring and M2 share the
`behaviour` group by default: reusing the same telemetry does not earn a bonus.
Duplicate IDs are collapsed, and conflicting reuse of an ID is rejected.

Scoring is scoped to one endpoint and immutable process identity per bundle.
An unrelated PID/boot/endpoint is excluded and retained in the explanation;
the upstream adapter must route it to its own case. Process corroboration
requires timestamps within the configured window. A PID-free M3 event can be
a `possible_link`, but cannot increase the identified process's score. Host-only
or uncorroborated high scores are capped below High Risk unless the explicit
single-signal policy is enabled. A valid attributed decoy write retains its
independent high-risk path. Explicit `registered: false` cannot authorize it.

The matrix consumes a normalized evidence **bundle**, not live module services:

* Envelope: `agent_id`, optional `case_id`, and `pid/start_ticks/boot_id` when an
  upstream adapter reliably identifies the target. Do not extract a PID from
  `run_id`, a display label, or a window's most frequent process.
* M2: native `/v1/predict` response under `ml`, or the flat equivalent. Probability,
  threshold and verdict must agree; an omitted M2 mode defaults to `alert_only`.
  Do not mix a model response with legacy `risk_score`. A legacy score alone is
  not a detector input to this matrix; the old standalone lab path is separate.
* M1: `monitoring` object/list with `event_id`, `rule_level` (0–16),
  `suspicious` (boolean), UTC `timestamp` and optional `process` identity object.
* M3: `honeyfile` object/list with decoy/path, operation, optional event ID,
  endpoint and UTC `timestamp`. Native local display `time` is retained in
  details but is not used as a UTC clock. Wazuh's event timestamp is the fallback.
  The separate `evidence` field retains the existing trusted `decoy_write`
  contract for independently attributed writes.
* M4: `threat_intel` object/list with `status`. A malicious match additionally
  needs `malicious: true`, provider, UTC `checked_at`, indicator type (`ip` or
  `sha256`) and exact indicator value. To corroborate a process it also needs an
  explicit matching `process` identity supplied by a trusted M1/M2 join. A
  context-free IOC, no-match, stale result or outage is not a benign verdict.

`source_id`/event IDs, timestamps, full matrix settings, contributions, groups,
correlation, missing/invalid sources and reasons are included in every result.
SHAP explains the ML contribution; its features are not counted again as
independent detectors. `partial_evidence` describes missing usable inputs, not
the health of remote services or a numerical confidence estimate.

Preview a recorded scenario **without root, SQLite writes, or responses**:

```bash
python3 ai_rdr_risk.py --input tests/fixtures/risk-matrix-example.json \
  --matrix config/risk-matrix.example.json --at 2026-11-11T10:00:00Z
python3 -m unittest discover -s tests -p test_risk_matrix.py -v
```

The fixture deliberately shows a host/time honeyfile link beside an alert-only
model. It remains Suspicious/record-only; its demo identity is not a live target.
Preview output sets execution flags false because no live OS validation occurs.

### Legacy Wazuh lab execution

`ai_rdr_fusion.py` is the legacy Wazuh entry point. Use command `ai_rdr_fusion` in
`ossec.conf.example` (rule 100105 is a placeholder), or the privileged local
`ai_rdr_response.py wazuh fusion` protocol adapter. Send one immutable source
alert ID and timezone-aware event timestamp with each evidence bundle. Do not
dispatch the same event to standalone playbooks or the separate central HTTP
responder as well. Fusion has no timer delete; use explicit case/operation
`thaw` or case-owned `undo`.

Normal/Suspicious/Unknown are recorded without containment. High Risk proposes
the reversible `high_action` (default Freeze; optionally isolate/block/disable
with a corresponding target). Kill is not a selectable first action. The
executor independently verifies the target and calls `ai_rdr_policy.py`:
matrix score cannot override `alert_only`, endpoint action permissions,
protected targets or approval requirements. Permitted non-decoy high-risk
freezes wait in REVIEW; they are not automatically killed or timed out as benign.
Attributed writes use the existing Freeze/Verify/containment workflow.
Even alternative host/account/IP actions require the scored process to remain
current. IP blocking additionally requires a fresh same-process IP match;
account restriction must target the scored process's actual UID.

AICM commits `risk.decided`, severity escalation and its outbox event in one
transaction before execution. Exact retries reuse the decision; case severity
is never automatically downgraded. Decisions remain in timeline/export/backup;
no database schema migration or central M6 connector is needed. Only a recorded,
matching, unexpired execution decision can bypass the legacy candidate-score
range inside the Freeze workflow. JSON cannot supply its own decision authority.

Keep all 15 runtime files together on the endpoint. Either configure a `risk_matrix`
object in `/etc/ai-rdr/config.json`, or remove that object and set
`"risk_matrix_file": "/etc/ai-rdr/risk-matrix.json"`, installing the example there
with the same restrictive ownership as the main configuration. Do not configure
both. Defaults are used when neither is set. The endpoint example supplies the
matrix version and inherits the prototype defaults. Do not enable ordinary
automatic actions simply to obtain a higher score; they remain a separate policy.

Optional `benign_guards` require an ID, exact endpoint and SHA256, UTC expiry,
and optional process/user selectors. Matches are audited; guards do not override
an attributed decoy write. These selectors depend on trusted upstream metadata
and need validation before use. The default guard list is empty.

Scenario tests verify policy behaviour, not ransomware detection accuracy.
The upstream normalization/attribution adapters and M4 provider are still external
integration dependencies. The M6 gateway below supplies an endpoint/client
transport; M6 must wire its backend routes and central projection to it. This
scorer does not fetch missing signals or resolve process identity independently.

Reference designs: [Splunk detection risk contributions](https://github.com/splunk/security_content/blob/develop/detections/endpoint/deleting_shadow_copies.yml)
and [Elastic entity risk scoring](https://github.com/elastic/docs-content/blob/main/solutions/security/advanced-entity-analytics/entity-risk-scoring.md).

### Available upstream inputs

The supplied full-project snapshot contains these interfaces. The matrix scores
their normalized bundles locally; live adapters still need to preserve these boundaries:

| Module | Actual data available | Boundary to preserve |
| --- | --- | --- |
| M1 | Deployment config enables auditd watches and Wazuh collection; index mappings declare agent/rule/process and normalized event fields. | Central `backend.irdp` / `backend.risk_fusion` sources are external and absent. A mapping is not proof that a field is populated. Event-time start ticks/boot identity still need an adapter. |
| M2 | `/v1/predict` returns probability, threshold, prediction, alert, `alert_only`, model/feature version, inference time and top SHAP feature/value contributions. | Response has no PID/agent/window identity. Requests may contain multiple PIDs; do not assign the window score to its most frequent PID. |
| M3 | Checkpoint 3 exposes decoy ID, path, READ/WRITE/DELETE/RENAME/MOVE operations, flags, display time and details through its Alert/callback. | No PID. CLOSE_WRITE semantics and second-resolution display time are not proof of event-time process attribution. |
| M4 | Deployment references a cached VirusTotal client; M6 has provisional indicator/type/reputation/source/last-checked/status contracts. | Real provider/normalizer code is not included; M6 values are mocks. Offline/no-match must not be treated as clean. |
| M6 | Provisional UI confidence, process-label, fusion-summary and response-state fields. | Display-only host matches, mock PIDs and mock action acceptance are neither evidence nor privileged response authorization. |

M2's write/read ratios, event rate, syscall entropy, rename/delete counts and
process-concentration features are model inputs. Only selected values may appear
in the top SHAP entries; the API does not return the complete feature vector.
Offline accuracy/precision/recall and response file-loss/timing measurements are
evaluation results, not per-incident detector scores to add into a risk matrix.

Index templates also declare `entropy_score`, `anomaly_score`, `confidence_level`,
`encryption_rate`, `feature_window_seconds`, `predicted_label`, `xforce_score`,
`lookup_status` and `cache_expiry`. These declarations do not establish working
producers. In particular, `confidence_level` is a float in normalized events but
a keyword in the ML index; neither is automatically M2's probability. The
deployment imports a VirusTotal client while the TI mapping declares
`xforce_score`. An adapter must resolve these semantics before scoring them.

`systemd/ai-rdr-worker.service` runs the deadline/recovery worker.
`ossec.conf.example` is a legacy manager-side integration template with
placeholder rule IDs. Set those IDs and the alert payload contract for a
dedicated Wazuh lab.

## M6 integration gateway

`ai_rdr_m6.py` provides a one-request JSON gateway on the endpoint and a portable
`M5Client` / `SSHTransport` for the M6 backend. It does not start another REST
server. M6 owns its HTTP routes, session authentication, browser authorization
and central dashboard projection. The client imports only standard-library
modules; the Linux executor is loaded only on the endpoint.

Transport: M6 backend -> verified SSH host/fixed command -> privileged M5
gateway -> local AICM/workflow. Every request and response is HMAC-SHA256 signed
with a provisioned endpoint key. Requests bind issuer, endpoint, principal,
roles, transport request ID, parameters and UTC expiry. The client uses a 60 s
lifetime; the endpoint accepts at most 120 s and 30 s of future clock skew.
Expiry is rechecked after waiting for the response lock and before dispatch.
The key and principal are backend-only; never derive roles from browser JSON.

### Backend methods and REST mapping

| Client call / gateway method | M6 REST route suggestion | Returns |
| --- | --- | --- |
| `list_cases(limit, offset)` | GET `/api/m5/cases` | Endpoint-scoped case rows |
| `get_case(case_id, limit)` | GET `/api/m5/cases/{id}` | Case lifecycle, latest risk decision, separate process/resource operations |
| `timeline(case_id, after, limit)` | GET `/api/m5/cases/{id}/timeline` | Ordered events and `next_after` cursor |
| `risk_decisions(case_id, after, limit)` | GET `/api/m5/cases/{id}/risk-decisions` | `risk.decided` events, including score, reasons and evidence |
| `request_action(case_id, action, ...)` | POST `/api/m5/cases/{id}/actions` | Durable request ID and execution outcome |
| `get_action(request_id)` | GET `/api/m5/actions/{id}` | completed / failed / uncertain, actor, executor and result |
| `outbox(limit)` / `acknowledge(event_ids)` | Internal connector, not a browser endpoint | At-least-once events and acknowledgements |
| `call('health')` | Backend integration health | Gateway readiness/boot ID; worker health is explicitly unobserved |

Pages are limited to 100 items and responses to 1 MiB. Case projections include
up to `limit` recent operations with `operation_count` / `operations_truncated`;
use the timeline for complete historical changes. Source/recording timestamps,
event IDs, case IDs, operation IDs and decision IDs are preserved. Persisted
APPLIED resource state is not represented as a continuous network-health probe.

Default roles (override `m6_gateway.role_permissions` on the endpoint if needed):

* `viewer`: reads.
* `analyst`: reads, Freeze, Verify, Thaw and Undo.
* `responder`: reads and all manual actions, including Kill and combined containment.
* `connector`: reads/event delivery; delivery requires a `service` principal.

Manual actions require a signed `user` principal and permission in both its role
and the endpoint's `m6_gateway.allowed_actions`. They do not enable automatic
response policy. Protected process/UID and immutable identity checks still apply.

### Action contract and state semantics

Every action requires `reason`, a stable `idempotency_key`, and the
`expected_sequence` from the case's current `last_sequence`. Refresh on a
sequence conflict. M5 derives the action request ID from endpoint/principal/key;
reuse of a key with a different body is rejected. JSON approval flags are not
accepted. The authenticated analyst is recorded as the event actor; the gateway
service and local Unix UID are recorded as executor.

| Action | Additional parameters | Effect |
| --- | --- | --- |
| `freeze` | `target` with exactly pid/start_ticks/boot_id; optional operation_id | Freeze and hold for manual review, even when ordinary automatic actions are off |
| `verify` | operation_id when ambiguous | Read current identities/stopped states and evidence; never kill or declare ransomware/benign |
| `kill` | operation_id when ambiguous | Terminate the identified, already-frozen operation; do not add network isolation |
| `isolate` | operation_id when ambiguous | Isolate the endpoint associated with a current frozen operation; do not terminate processes |
| `approve_containment` | operation_id when ambiguous | Explicit combined isolation + termination after Freeze/identity verification |
| `thaw` | operation_id when ambiguous | Resume owned processes; leave network/account restrictions alone |
| `undo` | resource_key, for example `isolate:host` | Release only this case's ownership of the selected restriction |

Manual Freeze holds are not automatically terminated when verification time
expires or decoy evidence is subsequently attached. A signed permitted manual
action must explicitly authorize termination. Case lifecycle, process state and
resource state remain separate; never map KILLED to Isolated or THAWED to Benign.

Requests execute synchronously, with durable requested/started/completed/failed
audit events. `completed` means this action returned verified results at its
recorded time; Verify's `identity_valid` may still be false. A delivered response
is not automatically an action success: inspect `status` and `result`. A lost
completion or interrupted executor produces `uncertain`, never a guessed pass.
Do not blindly retry effects: a repeated idempotency key returns the recorded
result, including uncertainty. An explicit Verify/new action requires a refreshed
case sequence. Failed/uncertain actions may have partial effects or later recovery;
inspect current operations and their audit history. There is no background job
queue hidden behind this gateway.

### M6 backend usage

Put the AI-RDR repository root on the backend's Python path (or install the
client module). M6 supplies `session_user_id` and `server_roles` from its own
authenticated session and server-side role mapping:

```python
from pathlib import Path
from m5.ai_rdr_m6 import M5Client, SSHTransport

client = M5Client(
    SSHTransport('endpoint.example', 'ai-rdr-m6', '/etc/ai-rdr/m6_ssh_key',
                 known_hosts_file='/etc/ai-rdr/known_hosts'),
    Path('/etc/ai-rdr/m6-gateway.key').read_bytes(),
    agent_id='001',
    principal={'type': 'user', 'id': session_user_id, 'roles': server_roles},
)
case = client.get_case(case_id)
result = client.request_action(
    case_id, 'freeze', target=verified_identity_from_m1_or_case,
    expected_sequence=case['case']['last_sequence'],
    reason=analyst_reason, idempotency_key=stable_ui_request_key,
)
# On a timeout, the backend can calculate/query this ID instead of repeating effects:
request_id = client.action_id(stable_ui_request_key)
status = client.get_action(request_id)
```

`GatewayError.code` supports HTTP mapping: unauthenticated=401, forbidden=403,
not_found=404, conflict=409, expired=408, bad_request=400,
unavailable/transport_uncertain=503. A valid response with `status: failed` is
an execution result, not an HTTP transport failure. Do not return role lists,
signing keys or raw SSH diagnostics to a browser.

For delivery, use a backend `service` principal with role `connector`. Persist
received event IDs and the central projection atomically, then acknowledge only
committed IDs. Retry unacknowledged batches; IDs make duplicates safe. Missing
events remain pending locally. M6 must implement this delivery loop and its
central projection; the gateway does not claim a central SQLite copy exists.

### Endpoint deployment

1. Install all **15** matching runtime Python files under
   `/opt/ai-rdr/m5/`, root:root, mode 750. Use `systemd/ai-rdr-worker.service`
   to run the worker from that directory.
2. Provision at least 32 random key bytes through the deployment/secret channel.
   The endpoint key must be a root-owned regular file, mode 600, at
   `/etc/ai-rdr/m6-gateway.key`. The M6 backend receives the same bytes in its
   own private service configuration. No key is stored in this repository.
3. Configure a dedicated SSH key/account and pin its host key in the backend's
   known_hosts. Restrict the authorized key to the fixed command below and grant
   sudo for exactly that command, without arbitrary command/path arguments:

   ```text
   /usr/bin/sudo -n /usr/bin/python3 /opt/ai-rdr/m5/ai_rdr_m6.py --config /etc/ai-rdr/config.json
   ```

   An authorized_keys entry can use `restrict,command="...fixed command..."`.
   Do not grant a general root shell. `SSHTransport` also sends only this fixed
   command; the JSON request goes through stdin, never shell interpolation.
   Roll out the new command together with the M6 client copy, endpoint
   authorized key, and sudoers rule.
4. Set `m6_gateway.enabled: true` in the endpoint configuration after provisioning;
   the example defaults to disabled. Keep the deadline/recovery worker running.
   The gateway itself is a one-shot SSH command; it needs no new public port or
   systemd web service.
5. Run the M6 gateway tests, then validate the actual SSH/account setup on a
   disposable endpoint before connecting browser actions:

   ```bash
   python3 -m unittest discover -s tests -p test_m6_gateway.py -v
   ```

Cloud tests use signed local transport and simulated OS effects. They do not
prove that your VM's SSH account, sudoers, key distribution, M6 authentication
or browser routes are configured. Those remain deployment/M6 integration work.

## Response evaluation

`tests/live_evaluate.py` measures generated-file damage, observed response time,
and verified reversal time. It writes per-run `manifest.json`, `synthetic-alert.json`
(when dispatched), `observations.jsonl`, `case.json`, and `result.json`, plus grouped
CSV/JSON summaries. Existing output folders are never overwritten. No pip packages
are required. The bounded workload overwrites disposable generated files; it is
not ransomware and does not validate a detector.

For a local check, run as a normal user from this source folder:

```bash
python3 tests/live_evaluate.py process-check --output artifacts/evaluation/local-01
```

This runs a matched no-response baseline and a real freeze/thaw experiment on its
own child, using the local Wazuh JSON adapter and real SQLite storage. It never
contacts a Wazuh manager or changes firewall/accounts. Final damage includes writes
after thaw. A brief freeze is not reported as permanent protection.

For Falco/ARM acceptance, correlate the observed Detection and ARM action ID
with approval, the verified endpoint effect, and undo. Measure those intervals
separately. The evaluator's `run` command below exercises legacy dispatch only.

### Legacy Wazuh endpoint

Run live experiments on the enrolled endpoint VM, with console access. Keep these
testing files in the source folder. Install the matching fifteen runtime files in
`/var/ossec/active-response/bin/`, root:wazuh, mode 750; the evaluator checks their
hashes so an older installed copy cannot silently produce misleading results.
Install the same runtime at `/opt/ai-rdr/m5/` for the current worker unit.
Pause response dispatch and stop the worker before replacing an existing runtime;
preserve `/etc/ai-rdr/config.json` and `/var/lib/ai-rdr/`, then restart the worker.

Prerequisites:

- Ubuntu 22.04/24.04, Python 3.10–3.12, enrolled Wazuh 4.x agent with Active Response
  enabled, manager API reachable, and `ai-rdr-worker.service` running for Freeze.
- A dedicated normal workload account, e.g. create it once with
  `sudo adduser --disabled-password --gecos '' ai-rdr-eval-writer`. The evaluator
  runs with sudo to read AICM and reverse restrictions; its writer drops to that UID.
- An evaluation configuration copied from `config/evaluation.example.json` outside
  Git. Set the actual agent ID, manager URL, trusted API CA certificate and account.
  Use a URL matching the API certificate. Credentials are supplied only through
  the named environment variable, never in the configuration or result files.
- A short-lived Wazuh API bearer credential authorised for `active-response:command`
  on this endpoint. Obtain it through your manager's existing authenticated login.
  Keep the manager API restricted to the lab management network.

For example, after editing a local configuration and obtaining the API credential:

```bash
read -rsp 'Wazuh API bearer credential: ' WAZUH_API_TOKEN
echo
export WAZUH_API_TOKEN
sudo --preserve-env=WAZUH_API_TOKEN /usr/bin/python3 tests/live_evaluate.py run \
  --config /etc/ai-rdr/evaluation.json --action baseline \
  --output artifacts/evaluation/baseline-01 --repetitions 1
sudo --preserve-env=WAZUH_API_TOKEN /usr/bin/python3 tests/live_evaluate.py run \
  --config /etc/ai-rdr/evaluation.json --action freeze \
  --output artifacts/evaluation/freeze-01 --repetitions 1
unset WAZUH_API_TOKEN
```

The API sends `PUT /active-response?agents_list=...` with the installed custom
executable and a labelled synthetic alert. It exercises manager-to-agent dispatch,
the JSON/check-keys adapter, OS action and AICM. HTTP acceptance means queued, not
contained. Reversal is an explicit local analyst CLI request; automatic Wazuh timer
expiry is not measured as manual reversal. Expired/closed evaluation additions are
rejected under the response lock; delete/undo remains permitted. Cleanup releases
only this run's leases and is never counted as a measured success.

Other `--action` values are `kill`, `isolate`, `block`, and `disable`:

| Action | Required effect checks |
|---|---|
| `freeze` | Owned writer stopped; after explicit thaw it is alive and making progress |
| `kill` | Owned writer exits with SIGKILL and isolation probes pass; no process reversal metric |
| `isolate` | Configured restricted probes fail while preserved management probes work |
| `block` | Restricted TCP probes address the actual `block_ip`; control probes remain usable |
| `disable` | A fresh-login command probe fails, while a preserved control probe succeeds |

Every network/account probe must work before the action. TCP probes establish new
connections, not existing-session coverage. Configure representative IPv4/IPv6
probes when those paths are available. A command probe uses an argv list without a
shell, for example `{"name":"fresh-login","type":"command","role":"restricted",
"argv":["/usr/bin/ssh","-o","BatchMode=yes","-o","ConnectTimeout=1",
"-i","/root/.ssh/evaluation_key","ai-rdr-eval-login@127.0.0.1","true"]}`.
Preconfigure the disposable user's key, known-host verification and a functioning
baseline login; choose a sufficient probe timeout. The disabled account must be a
separate non-administrator `ai-rdr-eval-*` account. Existing sessions are not revoked.

The sample probes suit isolation/kill only after a lab service listens on
`192.168.70.63:18080` and the manager accepts `:1514`. For an IP-block experiment,
change the restricted probe to the actual test peer at `block_ip`; for account
restriction, replace it with the fresh-login probe. Isolation and kill can cut the
endpoint's API connection on :55000; the observer still verifies endpoint effects
and records an uncertain API acknowledgement. Use the VM console for recovery.

After a pilot, use `--repetitions 30` with fresh output names and the same baseline
configuration/seed sequence. Aggregate a parent folder containing multiple runs:

```bash
python3 tests/live_evaluate.py summarize artifacts/evaluation
```

Summaries retain failures, missing effects, deadline misses and cleanup failures.
Latency distributions include all observed effects, even from failed runs; missing
effects have no fabricated duration. Damage reduction compares completed fixed-
horizon runs against matching baseline seeds/configuration only. p95 estimates
include their sample count. No p99 or ransomware-family effectiveness claim is made.
Record the actual observer gaps/probe durations alongside timings: polling resolution
limits precision. `effect_timeout_seconds` is the declared dispatch-to-effect and
reversal deadline for this experiment, not a Wazuh guarantee. The preserved
`frozen_seconds` field is workflow age, including freeze preparation; thaw now
also records its own execution `elapsed_ms`. Observed latency includes probe and
audit-visibility overhead, so retain the observer-gap evidence with the results.

These are response-stage measurements. Live detector latency and first-real-event
to containment still require the M1/M2/M3/M6 integration testbed. Isolation can pass
its network checks while local file damage continues; undo does not recover killed
processes or restore file contents. If cleanup fails, resolve the reported EVAL case
from the console before running another experiment. Normal alerts without evaluation
metadata keep their existing policy and approval requirements.
