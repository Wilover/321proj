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

`systemd/ai-rdr-worker.service` runs the deadline/recovery worker.
`ossec.conf.example` is a manager-side integration template with placeholder rule
IDs. Agree the alert payload and rule IDs before enabling it; do not enable a
second dispatch route alongside the existing central HTTP/SSH responder.
