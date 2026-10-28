import tempfile
import unittest
from pathlib import Path

from security_detector import detect_security_issues


class SecurityDetectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def scan(self):
        return detect_security_issues(self.root)

    def test_secret_detected_without_exposing_value(self):
        secret = "AbCdEfGh123456789XYZ"
        path = self.write(
            "config.py",
            "".join(("API_KEY", " = ", chr(34), secret, chr(34), "\n")),
        )
        original = path.read_text(encoding="utf-8")

        report = self.scan()
        titles = [item["title"] for item in report["findings"]]

        self.assertIn("সম্ভাব্য hardcoded API key", titles)
        self.assertNotIn(secret, repr(report))
        self.assertEqual(path.read_text(encoding="utf-8"), original)

    def test_shell_true_risk_detected(self):
        self.write(
            "commands.py",
            "import subprocess\n" + "".join(
                ("subprocess.run", "(command, shell=", "True)\n")
            ),
        )

        report = self.scan()
        self.assertTrue(any(
            "shell command injection" in item["title"]
            for item in report["findings"]
        ))

    def test_dynamic_execution_detected(self):
        self.write("dynamic.py", "".join(("result = eval", "(user_input)\n")))

        report = self.scan()
        self.assertTrue(any(
            "dynamic code execution" in item["title"]
            for item in report["findings"]
        ))

    def test_sql_interpolation_detected(self):
        self.write(
            "database.py",
           "".join(("cursor.", "execute", "(", chr(102), chr(34), "SELECT * FROM users WHERE id={user_id}", chr(34), ")\n")),
        )

        report = self.scan()
        self.assertTrue(any(
            "SQL string interpolation" in item["title"]
            for item in report["findings"]
        ))

    def test_tls_verification_disabled_detected(self):
        self.write(
            "network.py",
            "".join(("response = requests.get(url, verify=", "False\n")),
        )

        report = self.scan()
        self.assertTrue(any(
            "TLS" in item["title"]
            for item in report["findings"]
        ))

    def test_ignored_paths_are_not_scanned(self):
        self.write(".env.py","".join(("API_KEY", " = ", chr(34), "HiddenSecret123456789", chr(34), "\n")))
        self.write(".venv/unsafe.py", "".join(("eval", "(user_input)\n")))
        self.write("local.db", "not source code")

        report = self.scan()

        self.assertEqual(report["summary"]["files_scanned"], 0)
        self.assertEqual(report["findings"], [])

    def test_report_is_read_only(self):
        path = self.write("safe.py", "print('hello')\n")
        original = path.read_bytes()

        report = self.scan()

        self.assertTrue(report["read_only"])
        self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
