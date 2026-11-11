# AI-RDR M5

M5 contains Wazuh response playbooks (isolate, kill, block IP, disable account),
the freeze → verify → contain/thaw workflow, and AICM case records with a SQLite
audit trail. All twelve runtime Python files stay together because they share imports.

Use Ubuntu 22.04/24.04 with Python 3.10–3.12 and an enrolled Wazuh agent for live
responses. No pip dependencies are required. Windows VS Code can connect to the
Ubuntu VM through Remote SSH.

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

`config/lab.example.json` is an endpoint configuration example; edit its IPs,
agent ID and protected accounts before use. Attributed decoy evidence permits
automatic process containment by default; `require_approval` or `critical_asset`
adds a process-containment approval gate. Process alerts require `pid`,
`start_ticks` and `boot_id`; decoy evidence must match that identity.

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
configurations. The supplied endpoint example keeps ordinary automatic actions
disabled; the evaluator does not change installed endpoint policy for you.

### Available upstream inputs for a future risk matrix

The supplied full-project snapshot contains these interfaces; they are not yet
a connected multi-source risk matrix in this repository:

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
`ossec.conf.example` is a manager-side integration template with placeholder rule
IDs. Agree the alert payload and rule IDs before enabling it; do not enable a
second dispatch route alongside the existing central HTTP/SSH responder.

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

### Live Wazuh endpoint

Run live experiments on the enrolled endpoint VM, with console access. Keep these
testing files in the source folder. Install the matching twelve runtime files in
`/var/ossec/active-response/bin/`, root:wazuh, mode 750; the evaluator checks their
hashes so an older installed copy cannot silently produce misleading results.
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
