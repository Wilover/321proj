import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ManualDemonstrationTests(unittest.TestCase):
    def test_all_simulated_tasks_emit_verified_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            for task, count in (('playbooks', 5), ('freeze', 7), ('aicm', 5)):
                with self.subTest(task=task):
                    output = Path(folder) / task
                    result = subprocess.run([sys.executable, 'tests/manual_m5.py', task,
                        '--non-interactive', '--output', str(output)], cwd=ROOT,
                        capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    evidence = json.loads((output / 'results.json').read_text())
                    self.assertTrue(evidence['passed'])
                    self.assertEqual(evidence['task'], task)
                    self.assertEqual(len(evidence['results']), count)
                    self.assertEqual(evidence['mode'], 'simulated-host-real-m5-and-sqlite')
                    self.assertTrue(list(output.glob('case-*.json')))
                    self.assertIn('not production attack-to-containment', (output / 'report.md').read_text())

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'earlier-results.txt'
            marker.write_text('preserve earlier observations')
            result = subprocess.run([sys.executable, 'tests/manual_m5.py', 'playbooks',
                '--non-interactive', '--output', folder], cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(marker.read_text(), 'preserve earlier observations')
            self.assertIn('Output folder already exists', result.stderr)

    def test_real_process_option_belongs_to_freeze_task(self):
        result = subprocess.run([sys.executable, 'tests/manual_m5.py', 'playbooks', '--real-process',
            '--non-interactive'], cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('only supported for the freeze task', result.stderr)
