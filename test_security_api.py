import os
import unittest
from unittest.mock import patch

import app as app_module
import project_intelligence as pi


class SecurityScanAPITests(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        self.client = app_module.app.test_client()
        app_module.app.config["OWNER_USERNAME"] = "test-owner"
        from werkzeug.security import generate_password_hash
        app_module.app.config["OWNER_PASSWORD_HASH"] = generate_password_hash(
            "test-only-password"
        )
        with self.client.session_transaction() as sess:
            sess["owner_authenticated"] = True
            sess["owner_username"] = "test-owner"
            sess["csrf_token"] = "test-csrf-token"

    def test_security_scan_returns_read_only_report(self):
        response = self.client.post(
            "/api/project-intelligence/security-scan"
        )
        self.assertEqual(response.status_code, 200)
        report = response.get_json()
        self.assertEqual(report["status"], "ok")
        self.assertTrue(report["read_only"])
        self.assertEqual(
            report["analysis_type"],
            "heuristic_static_analysis",
        )
        self.assertIn("findings", report)
        self.assertIn("summary", report)
        self.assertIsInstance(report["findings"], list)

    def test_security_scan_is_post_only(self):
        response = self.client.get(
            "/api/project-intelligence/security-scan"
        )
        self.assertEqual(response.status_code, 405)

    def test_security_advice_returns_503_without_ai_provider(self):
        with patch.object(
            app_module, "ai_is_configured", return_value=False
        ):
            response = self.client.post(
                "/api/project-intelligence/security-advice"
            )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.get_json()["status"], "unavailable"
        )

    def test_security_advice_returns_ai_reply(self):
        with patch.object(
            app_module, "ai_is_configured", return_value=True
        ):
            with patch.object(
                app_module, "call_ai", return_value="ঝুঁকি যাচাই করুন।"
            ) as mocked:
                response = self.client.post(
                    "/api/project-intelligence/security-advice"
                )

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertTrue(data["read_only"])
        self.assertEqual(data["advice"], "ঝুঁকি যাচাই করুন।")
        self.assertNotIn("source_code", data)
        mocked.assert_called_once()

    def test_security_advice_hides_provider_error(self):
        with patch.object(
            app_module, "ai_is_configured", return_value=True
        ):
            with patch.object(
                app_module,
                "call_ai",
                side_effect=RuntimeError("private provider detail"),
            ):
                response = self.client.post(
                    "/api/project-intelligence/security-advice"
                )

        self.assertEqual(response.status_code, 502)
        self.assertNotIn(
            "private provider detail",
            response.get_data(as_text=True),
        )



    def test_test_runner_is_disabled_without_enable_flag(self):
        with patch.dict(os.environ, {
            "NH_ENABLE_TEST_RUNNER": "0",
            "NH_TEST_RUNNER_TOKEN": "x" * 40,
        }):
            response = self.client.post(
                "/api/project-intelligence/test-run",
                headers={"X-NH-Test-Token": "x" * 40},
            )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["status"], "disabled")

    def test_test_runner_rejects_wrong_token(self):
        with patch.dict(os.environ, {
            "NH_ENABLE_TEST_RUNNER": "1",
            "NH_TEST_RUNNER_TOKEN": "correct-token-" + "x" * 32,
        }):
            response = self.client.post(
                "/api/project-intelligence/test-run",
                headers={"X-NH-Test-Token": "wrong-token"},
            )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["status"], "forbidden")

    def test_test_runner_executes_allowlisted_tests_with_valid_token(self):
        from types import SimpleNamespace

        token = "test-token-" + "a" * 32
        fake_result = SimpleNamespace(
            returncode=0,
            stdout="",
            stderr="Ran 25 tests in 1.2s",
        )
        with patch.dict(os.environ, {
            "NH_ENABLE_TEST_RUNNER": "1",
            "NH_TEST_RUNNER_TOKEN": token,
        }):
            with patch.object(pi.subprocess, "run", return_value=fake_result) as mocked:
                response = self.client.post(
                    "/api/project-intelligence/test-run",
                    headers={"X-NH-Test-Token": token},
                )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["passed"])
        self.assertEqual(response.get_json()["tests_run"], 25)
        command = mocked.call_args.args[0]
        self.assertIn("test_security_api.py", command)
        self.assertIn("test_auth.py", command)
        self.assertIn("test_security_detector.py", command)
        self.assertFalse(mocked.call_args.kwargs["shell"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
