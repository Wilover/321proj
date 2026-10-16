# Deploy AI-RDR M5 to Ubuntu

This guide maps the current repository to an Ubuntu VM. It covers ARM, the
freeze/verify worker and AICM. It does not install Wazuh itself, the M2 detector,
M3 decoy monitoring or M6's dashboard/API. Install/enrol Wazuh with M1 first.

Recommended initial layout: a **Wazuh manager VM** and a separate **Ubuntu 22.04
or 24.04 monitored endpoint VM**. Run the responses on the endpoint being protected.
Ubuntu's system Python is 3.10 on 22.04 and 3.12 on 24.04; both fit this code.
Python 3.13+ is unsupported for account actions because `spwd` was removed.
Use a full VM with systemd and its own network stack, rather than a container.

The commands below assume a normal user account, the standard Wazuh prefix
`/var/ossec`, and a source checkout at `~/321proj`. Replace account names/IPs with
your actual values. Changes to the Ubuntu VM must be run there; changing files in
this cloud checkout does not install anything on your VM.

## 1. Which files go where

| Repository file(s) | Destination | Machine / purpose |
|---|---|---|
| `ai_rdr_freeze.py`, `ai_rdr_kill.py`, `ai_rdr_isolate.py`, `ai_rdr_block_ip.py`, `ai_rdr_disable_user.py` | `/var/ossec/active-response/bin/` | Endpoint: five Wazuh executable entry points |
| `ai_rdr_response.py`, `ai_rdr_actions.py`, `ai_rdr_common.py`, `ai_rdr_aicm.py`, `freeze_verify_manager.py` | Same directory as the entry points | Endpoint: imported shared modules and deadline worker; all five are required |
| `ai_rdr_case.py` | Same directory | Endpoint: local case/timeline/export/backup CLI |
| `config/lab.example.json` | Copy to `/etc/ai-rdr/config.json`, then edit | Endpoint: per-VM configuration |
| `systemd/ai-rdr-worker.service` | `/etc/systemd/system/ai-rdr-worker.service` | Endpoint: deadline/recovery service |
| `ossec.conf.example` | Merge its blocks into existing `/var/ossec/etc/ossec.conf` | **Manager**: command definitions and Active Response triggers; this file is a fragment, not a replacement config |
| `tests/`, `docs/`, `README.md`, `.gitignore`, `.git/` | Keep in the source checkout | Development/reference; do not put them in the Active Response executable directory |

Generated files belong on the endpoint, not in Git:

- `/var/lib/ai-rdr/aicm.sqlite3` and its `-wal`/`-shm` sidecars: cases, audit and ARM state.
- `/var/lib/ai-rdr/response.lock`: serialises endpoint actions.
- Existing `state.json`: imported once if present, then retained as a legacy archive.
- Worker diagnostics: `journalctl -u ai-rdr-worker`; Wazuh diagnostics:
  `/var/ossec/logs/ossec.log` and, where written by Wazuh, `active-responses.log`.

New audit history is in SQLite. `audit_log` does **not** produce a new JSONL log.
Use the case CLI to inspect/export it.

Do not transfer a running endpoint's database/lock/state to a different VM as
configuration. They contain endpoint-specific process identities and action
ownership. Start a fresh endpoint with its own state directory. Restoring the same
endpoint is a separate recovery operation, not a fresh installation.

## 2. Values you must review

Copy the example before editing; keep the repository example reusable.

| Setting in `/etc/ai-rdr/config.json` | Current example | What to use on your VM |
|---|---|---|
| `manager_addresses` | `["192.168.10.10"]` | The actual manager IP address(es) that the endpoint connects to; literal IPv4/IPv6 addresses, no hostname, URL or CIDR. Include IPv6 if the agent uses it. Loopback addresses are rejected. |
| `manager_ports` | `[1514]` | Actual **TCP destination ports** used by this agent for manager communication. Default agent traffic is TCP 1514. Port 1515 is optional enrolment traffic, not a replacement for 1514. The code does not support UDP manager exceptions. |
| `agent_id` | `"001"` | This endpoint's actual Wazuh agent ID, as a **string preserving leading zeros**. It must equal `alert.agent.id`. Each endpoint needs its own file. |
| `policy_version` | `"candidate-v1"` | A label for the policy you are testing. Change it when changing decision/timing policy; changing the label alone changes no behaviour. |
| `verification_seconds` | `3` | Verification deadline, in seconds; accepted range is greater than 0 and at most 10. This is not total attack-to-containment time. |
| `timeout_policy` | `"thaw"` | Choose explicitly: `thaw` resumes after inconclusive timeout; `review` keeps the process frozen until an analyst acts. The latter has no automatic maximum freeze duration. |
| `minimum_process_uid` | `1000` | Processes with UID below this are protected. Keep 1000 for the initial lab and run the harmless test workload as a normal user with UID >=1000. This excludes root-run ransomware from automatic process containment. |
| `critical_asset` | `false` | Set true if this endpoint requires analyst approval before process-tree hard containment. This flag does **not** gate independently triggered isolate/block/disable actions. |
| `protected_processes` | `sshd`, `systemd`, `ai_rdr_response` | Add essential process **comm names**, not paths, PIDs or command-line arguments. Inspect `/proc/<pid>/comm`. Interpreted programs may appear as `python3`; Linux comm names may be truncated. Do not assume a Python script filename protects it. Protect critical service accounts by UID as well. |
| `protected_users` | `root`, `wazuh`, `ai-rdr` | Add the VM administrator/recovery account, test controller and other accounts that account restriction must never touch. This list applies to account actions, not process actions. |
| `state_dir` | `/var/lib/ai-rdr` | Keep this initially; it must be root-only on local writable disk. If changed, create the new directory and pass `--database <new-dir>/aicm.sqlite3` to the case CLI. |
| `audit_log` | `/var/log/ai-rdr/response.jsonl` | Legacy compatibility field; ignored for new audit storage. It is not an OpenSearch exporter or log destination. |

Find the agent ID in the Wazuh dashboard, or list agents **on the manager**:

```bash
sudo /var/ossec/bin/agent_control -l
```

Use M1's configured manager address/port and check the endpoint's existing
`<client><server>` configuration. Do not dump the entire Wazuh directory or
`client.keys` to discover the ID; that is unnecessary and can expose agent keys.

There is no `WAZUH_MANAGER_IP` or `HONEY_FILE` constant to change in this version.
Manager addresses come from JSON; M3/M1 provide attributed decoy evidence. There
is no implemented X-Force/enrichment adapter to configure in M5.

## 3. Source defaults and hardcoded limits

These are code/policy defaults, not values that must be replaced for each VM.
Changing them is a code change: retest, reinstall the changed module and restart
the worker. Do not add invented JSON keys and expect the code to read them.

| Location in repository | Fixed/default behaviour | Deployment implication |
|---|---|---|
| `ai_rdr_common.py`: `Runtime.__init__` | Config defaults to `/etc/ai-rdr/config.json`; state defaults to `/var/lib/ai-rdr` | Prefer these paths. `AI_RDR_CONFIG` overrides config lookup; `ai_rdr_response.py --config ...` works for an explicit CLI invocation. A shell export alone will not configure Wazuh/systemd. |
| `ai_rdr_case.py`: `main` | Default DB `/var/lib/ai-rdr/aicm.sqlite3` | This CLI does not read the runtime JSON; use `--database` for a custom state directory. |
| `systemd/ai-rdr-worker.service` | `/usr/bin/python3`, `/var/ossec/active-response/bin/ai_rdr_response.py`, root, restart after 1 s | Edit the unit if Python/Wazuh paths differ; run daemon-reload after unit changes. |
| Executable `.py` headers | `#!/usr/bin/env python3` | Wazuh resolves Python from its PATH. The install steps below pin installed entry points to the verified `/usr/bin/python3`. Shared modules are imported from the same directory. |
| `freeze_verify_manager.py`: `Workflow.freeze` | Candidate score `0.60 <= score < 0.90` unless attributed confirming evidence exists | A score >=0.90 alone does not authorise kill. Thresholds require calibration with M2, not a per-VM IP edit. |
| Same method | At most 128 discovered processes and a 2 s traversal budget; verification window capped at 10 s | Large/busy process trees may fail and roll back; do not call this atomic cgroup containment. |
| `ai_rdr_common.py`: `run` | 2 s timeout per system command | This is not a 2 s total playbook budget. |
| `ai_rdr_common.py`: `wait_effect` / `wait_resumed` | 0.5 s verification, 10 ms polling | Uninterruptible I/O/busy VMs can exceed this. |
| `ai_rdr_response.py`: `read_message` / worker loop | 5 s initial readiness wait, 65,536-character line cap; 100 ms worker sleep | Timings are not hard real-time guarantees. The read implementation does not impose a complete deadline on a partially delivered line. |
| `ai_rdr_actions.py`: `account_snapshot` | UID below 1000 always protected; local shadow/PAM-based account restriction | This **does not use** `minimum_process_uid`. Do not lower the process threshold expecting it to change account eligibility. Existing sessions are not killed. |
| `ai_rdr_actions.py`: `firewall` | `iptables` and `ip6tables`, 1 s lock wait, `AI_RDR_*` chain names, local INPUT/OUTPUT | Both backends must work. Reserve these chains; routed/bridged/container FORWARD traffic is outside this playbook. |
| `ai_rdr_common.py`: `identity` / `protected` / `signal_identity` | PID <=1, own PID, configured comm names and `wazuh-*` protection | These guards remain even if the process UID threshold is changed. |
| `ai_rdr_aicm.py` | Schema v1; SQLite busy wait 5 s; 1 MiB encoded record cap; 256-character general IDs; query page max 1000 | Keep initially. Case IDs accepted by ARM are additionally capped at 128 characters. No automatic retention/remote export is implemented. |
| `ossec.conf.example` | Rule IDs 100100–100104; block timeout 300 s; account timeout 600 s | Replace rule IDs with M1's actual rules and choose timer policy with the team. These are placeholders/example durations. |

Linux `/proc` paths are kernel interfaces. Do not replace them with checkout or
Ubuntu installation paths. There are no required pip packages or API keys.

## 4. Prepare the endpoint

Install the OS prerequisites on the endpoint:

```bash
sudo apt-get update
sudo apt-get install -y git python3 iptables passwd procps
```

Obtain the checkout on the endpoint, using Git or a file transfer. For example,
if it is not already present:

```bash
git clone https://github.com/Wilover/321proj.git ~/321proj
cd ~/321proj
```

If already cloned, use its actual directory and update the intended branch without
overwriting local modifications. Verify the runtime and Wazuh prerequisites:

```bash
/usr/bin/python3 --version
uname -r
getent group wazuh
sudo test -d /var/ossec/active-response/bin
sudo systemctl status wazuh-agent --no-pager
```

The `wazuh` group, directory and service must come from the actual Wazuh agent
installation; do not fabricate them to make these checks pass. If this machine is
only the manager, switch to the monitored endpoint for installation.

Check Python/kernel features without sending a signal:

```bash
/usr/bin/python3 - <<'PY'
import os, signal, sqlite3, sys
assert (3, 10) <= sys.version_info[:2] < (3, 13), sys.version
assert hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal')
import spwd  # Expected deprecation warning on newer supported Python versions.
fd = os.pidfd_open(os.getpid())
os.close(fd)
print('Python, SQLite and kernel pidfd support checked:', sqlite3.sqlite_version)
PY
sudo iptables -w 1 -S
sudo ip6tables -w 1 -S
```

Do not disable TLS/package verification, IPv6 or the firewall to bypass a failure.
Fix the VM/kernel/backend prerequisite first. If UFW, Docker or nftables tooling
also manages this VM, inspect it with M1 and validate rule ordering; do not switch
iptables alternatives or flush rules blindly. No new inbound AI-RDR port is needed.

Run the repository tests **as your normal user**, not sudo:

```bash
/usr/bin/python3 -m unittest discover -s tests -v
```

Tests mock firewall/account changes; kernel tests only signal child `sleep`
processes they create. This checks code on your Ubuntu VM, not Wazuh integration.

## 5. Install the endpoint files

Take a disposable VM snapshot before live response tests. Have a hypervisor console
available: isolation intentionally cuts ordinary SSH, including existing sessions.
Adding port 22 to `manager_ports` does not create an inbound SSH exception.

For an upgrade on the same VM, stop the old worker and prevent M1's response rules
from dispatching during replacement. Inspect current state first; keep database
and lease state. Use the existing case CLI's `backup` command for a SQLite backup;
do not copy just the main database while WAL writes are active.

From the source checkout on the endpoint:

```bash
sudo systemctl stop ai-rdr-worker.service
sudo install -d -o root -g root -m 700 /etc/ai-rdr /var/lib/ai-rdr
```

On a first installation, `systemctl stop` can report that the unit does not exist;
that is expected. On an upgrade, check `systemctl is-active ai-rdr-worker` to
report inactive before copying files. Do not treat an actual stop failure as safe.

Create configuration **only if it does not already exist**:

```bash
if ! sudo test -e /etc/ai-rdr/config.json; then
    sudo install -o root -g root -m 600 config/lab.example.json /etc/ai-rdr/config.json
fi
sudoedit /etc/ai-rdr/config.json
```

Apply the table in section 2, especially manager address, agent ID and protected
administrator account. Confirm you intentionally chose thaw or review on timeout.
Validate JSON syntax and install all eleven Python files together:

```bash
sudo /usr/bin/python3 -m json.tool /etc/ai-rdr/config.json >/dev/null
sudo install -o root -g wazuh -m 750 ai_rdr_*.py freeze_verify_manager.py /var/ossec/active-response/bin/
```

Pin the installed executable entry points to the system Python you verified.
This edits only the installed copies, not the source checkout:

```bash
for name in ai_rdr_freeze.py ai_rdr_kill.py ai_rdr_isolate.py ai_rdr_block_ip.py ai_rdr_disable_user.py ai_rdr_response.py ai_rdr_case.py; do
    sudo sed -i '1s@^#!/usr/bin/env python3$@#!/usr/bin/python3@' "/var/ossec/active-response/bin/$name"
done
```

Do not run recursive chmod/chown over `/var/ossec`. Do not make code, config or
SQLite writable by monitored users. Leave unrelated Wazuh scripts alone.

Install/start the worker:

If you previously customised this unit, compare and merge those changes before
replacing it. Keep any known required unit/drop-in settings.

```bash
sudo install -o root -g root -m 644 systemd/ai-rdr-worker.service /etc/systemd/system/ai-rdr-worker.service
sudo systemctl daemon-reload
sudo systemctl enable --now ai-rdr-worker.service
sudo systemctl status ai-rdr-worker.service --no-pager
sudo journalctl -u ai-rdr-worker.service -n 50 --no-pager
sudo /usr/bin/python3 /var/ossec/active-response/bin/ai_rdr_response.py status
```

The worker handles deadlines/recovery; a running worker alone does not prove
Active Response is configured. Root runs are required for actual process/firewall/
account actions. The database is created automatically; no SQL init command is needed.

## 6. Configure the Wazuh manager

On the **manager**, back up the existing config and open it:

```bash
sudo cp -a /var/ossec/etc/ossec.conf "/var/ossec/etc/ossec.conf.ai-rdr-backup-$(date +%Y%m%d-%H%M%S)"
sudoedit /var/ossec/etc/ossec.conf
```

Merge `ossec.conf.example` blocks inside the existing `<ossec_config>` structure.
Do not replace the whole config or include a second conflicting definition of
the same command. Have M1 provide actual detection rules/decoders; the example
file does not define those rules.

| Command | Example triggering rule | Required routing |
|---|---|---|
| `ai_rdr_freeze` | 100100 | Behavioural candidate; do not set Wazuh timeout, because the worker owns it |
| `ai_rdr_kill` | 100101 | Attributed positive evidence or existing analyst approval; no timeout/undo |
| `ai_rdr_isolate` | 100102 | High-confidence network isolation; explicit undo in this template |
| `ai_rdr_block_ip` | 100103 | Validated source IP; example automatic delete after 300 s |
| `ai_rdr_disable_user` | 100104 | Eligible local username; example automatic restore after 600 s |

Keep `<location>local</location>`: this means the endpoint that generated the
alert, **not** the manager merely because its configuration is edited there.
Do not use `all`. If M2/M3 generate alerts as manager-local events, `local` could
target the manager; M1/M6 must preserve the original agent route or implement a
verified per-endpoint dispatch integration. A JSON `agent.id` field alone is not
proof that the Wazuh execution route reaches that endpoint.

Validate the config using the installed Wazuh tools before restarting:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo /var/ossec/bin/wazuh-execd -t
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager --no-pager
```

Run restart only if both validation commands succeeded. On the endpoint, also
check `sudo /var/ossec/bin/wazuh-execd -t` and confirm Active Response has not been
disabled by its agent/shared configuration. Coordinate central agent settings with
M1 rather than appending conflicting blocks blindly.

## 7. Agree the incoming alert contract

An arbitrary stock Wazuh alert is not sufficient for all these playbooks. M1/M2/M3
must provide the fields consumed in `ai_rdr_response.py` and `Workflow.confirmed`:

| Input | Used for |
|---|---|
| `parameters.alert.id`, `timestamp`, `agent.id` | Deduplication, timezone-aware occurrence time, correct endpoint identity |
| `parameters.alert.data.case_id` | Group related alerts/roots into one incident; can be omitted for conservative generated correlation |
| `data.pid`, `data.start_ticks`, `data.boot_id` | Immutable process identity for freeze/kill, collected at event time |
| `data.risk_score` | Candidate policy; numeric value in [0.60, 0.90) without confirming evidence |
| `data.evidence` | For automatic kill: `type="decoy_write"`, `event_id`, matching numeric `pid`/`start_ticks` and matching `boot_id` |
| `data.src_ip` | Block action; this exact field is used, not the stock `srcip` name |
| `data.username` | Account restriction; this exact field is used, not an arbitrary nested username |
| `data.model_version` | Optional model version stored with the alert |

Use JSON integers for process identities and numeric evidence fields. Verify the
actual decoded payload, because string `"4128"` in evidence does not equal integer
`4128` in this verifier. Use timezone-bearing ISO timestamps. Supplying an alert
ID without a timestamp is rejected. High ML score alone is not positive evidence.
No secret/API key should be added to these alerts.

Do not hardcode the example PID, boot UUID, Case ID or process start ticks from a
README into rules. M1/M3 must capture the real values on the affected endpoint.

The scripts use Wazuh's newline JSON/check-keys protocol. They do not accept the
old example syntax `ai_rdr_isolate.py add` or `ai_rdr_kill.py 4128`. Analyst commands
go through `ai_rdr_response.py`; Wazuh executable wrappers normally run without args.

## 8. Verify the deployment in stages

First check local case storage without applying any response:

```bash
sudo /usr/bin/python3 /var/ossec/active-response/bin/ai_rdr_case.py create --title "Ubuntu deployment check"
sudo /usr/bin/python3 /var/ossec/active-response/bin/ai_rdr_case.py list
```

Use the generated Case ID to inspect its `show`/`timeline` output. This case proves
DB/CLI operation only. The script is root-owned; use sudo for the protected DB.

Next, with M1, send a genuine freeze alert for a harmless `sleep` process created
by a normal lab user. Capture that process's real identity, use a candidate score
such as 0.75, and provide no decoy evidence. Verify:

1. Wazuh routes it to the correct endpoint and receives the script's check-keys reply.
2. The process is stopped, a case/operation is recorded, and the worker handles
   timeout according to the configured policy.
3. A retry does not stop a second process or duplicate the alert record.
4. In review mode, use the actual operation ID to thaw, then inspect the audit.

```bash
sudo /usr/bin/python3 /var/ossec/active-response/bin/ai_rdr_case.py show CASE-ID
sudo /usr/bin/python3 /var/ossec/active-response/bin/ai_rdr_case.py timeline CASE-ID
sudo /usr/bin/python3 /var/ossec/active-response/bin/ai_rdr_response.py thaw CASE-ID --operation OPERATION-ID --reason "Harmless lab verification"
```

Only after that, test kill on another disposable child, IP block against a lab
test address, account restriction against a disposable non-administrator account,
and host isolation from the VM console. Verify both allowed manager traffic and
forbidden existing/new IPv4/IPv6 traffic. Test real PAM/SSH-key login denial;
password lock/expiry does not terminate existing sessions.

Isolation recovery from the **endpoint console**, using the real owning Case ID:

```bash
sudo /usr/bin/python3 /var/ossec/active-response/bin/ai_rdr_response.py undo CASE-ID --reason "Isolation test complete"
```

`undo` releases that case's reversible leases; it does not thaw processes or
restore killed ones. Another case may still own isolation. Do not flush the global
firewall or delete the database to recover connectivity.

Stopping/uninstalling the worker does not undo actions. Inspect/resolve active
cases before maintenance. After an endpoint reboot or an external firewall reload,
check the real firewall against retained leases: current reconciliation retries
PENDING/REMOVING resources, but does not automatically reinstall an APPLIED rule
lost during a reboot. Do not claim containment from the stored status alone.

M6 HTTP authentication, remote event transport, central case projections and
OpenSearch export remain separate integration work. Keep the database local;
copying `ai_rdr_aicm.py` onto a manager does not create a central API service.

## 9. Common problems

| Symptom | Check |
|---|---|
| Agent ID differs from configuration | Actual `alert.agent.id` versus JSON string; leading zeros and which endpoint executed the command |
| No response although worker is running | Actual manager rule ID, agent routing, `<disabled>`, and Wazuh logs; worker startup does not configure triggers |
| ModuleNotFoundError | All eleven Python files installed together in the same directory, not only wrappers |
| Protected process/account | Process UID/comm guard versus separate fixed account UID guard; use a disposable normal-user workload |
| Kill rejected | Actual attributed decoy evidence/approval, critical-asset policy and numeric types; do not bypass the guard by changing a risk score |
| `spwd` import failure | Wazuh wrapper's actual interpreter; use system Python 3.10–3.12 |
| ip6tables/backend error | VM kernel/backend availability; IPv4-only networking does not eliminate the code's IPv6 backend requirement |
| Empty case CLI while ARM has cases | Wrong CLI database path; `--database` must match `state_dir` |
| No new `response.jsonl` | Expected: AICM audit is in SQLite |
| SSH lost during isolation | Expected: use VM console and case-owned undo |
| App/dashboard disconnected after isolation | Only loopback and configured manager TCP traffic are allowed; remote M6/TI destinations are not automatically exempted |

Reference checked for manager/endpoint placement and location semantics:
[Wazuh configuration documentation, 4.9 source](https://github.com/wazuh/wazuh-documentation/blob/4.9/source/user-manual/capabilities/active-response/how-to-configure.rst).
Match syntax and support to M1's installed Wazuh version. These instructions were
reviewed against the repository; actual Ubuntu/Wazuh readiness requires the checks
above on your VM.
