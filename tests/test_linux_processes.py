"""Kernel checks signal ONLY disposable child processes created by each test."""
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest

from ai_rdr_common import Runtime
from freeze_verify_manager import Workflow


@unittest.skipUnless(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'),
                     'Linux pidfd support required')
class LinuxProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.child = subprocess.Popen(['sleep', '60'])
        def cleanup():
            if self.child.poll() is None:
                self.child.kill()
            self.child.wait(timeout=2)
        self.addCleanup(cleanup)
        directory = Path(self.temp.name)
        self.r = Runtime({'state_dir': str(directory), 'audit_log': str(directory / 'audit.jsonl'),
                          'minimum_process_uid': os.getuid(), 'verification_seconds': 3,
                          'timeout_policy': 'thaw'})
        self.w = Workflow(self.r)
        self.state = {'resources': {}, 'cases': {}}
        self.identity = self.r.identity(self.child.pid)

    def freeze(self):
        item = self.identity
        return self.w.freeze(self.state, 'kernel-test', item['pid'], item['start_ticks'],
                             item['boot_id'], .75)

    def test_real_freeze_then_resume(self):
        self.freeze()
        self.assertIn(self.r.identity(self.child.pid)['state'], ('T', 't'))
        self.w.thaw(self.state, 'kernel-test', 'test complete')
        self.assertNotIn(self.r.identity(self.child.pid)['state'], ('T', 't'))
        self.assertIsNone(self.child.poll())

    def test_real_approved_termination(self):
        record = self.freeze()
        record['analyst_approved'] = True
        self.w.contain(self.state, 'kernel-test', isolate=False)
        self.assertEqual(self.child.wait(timeout=2), -signal.SIGKILL)

    def test_pidfd_rejects_wrong_identity(self):
        wrong = dict(self.identity, start_ticks=self.identity['start_ticks'] + 1)
        with self.assertRaises(ValueError):
            self.r.signal_identity(wrong, signal.SIGKILL)
        self.assertIsNone(self.child.poll())
