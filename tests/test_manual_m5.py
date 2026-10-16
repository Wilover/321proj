import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ManualDemonstrationTests(unittest.TestCase):
    def test_all_simulated_milestones_emit_verified_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            for week, count in (('week1', 4), ('week2', 5), ('week3', 4), ('week4', 4)):
                with self.subTest(week=week):
                    output = Path(folder) / week
                    result = subprocess.run([sys.executable, 'tools/manual_m5.py', week,
                        '--non-interactive', '--output', str(output)], cwd=ROOT,
                        capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    evidence = json.loads((output / 'results.json').read_text())
                    self.assertTrue(evidence['passed'])
                    self.assertEqual(len(evidence['results']), count)
                    self.assertEqual(evidence['mode'], 'simulated-host-real-m5-and-sqlite')
                    self.assertTrue(list(output.glob('case-*.json')))
                    self.assertIn('not production attack-to-containment', (output / 'report.md').read_text())

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'earlier-results.txt'
            marker.write_text('preserve earlier observations')
            result = subprocess.run([sys.executable, 'tools/manual_m5.py', 'week1',
                '--non-interactive', '--output', folder], cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(marker.read_text(), 'preserve earlier observations')
            self.assertIn('Output folder already exists', result.stderr)
