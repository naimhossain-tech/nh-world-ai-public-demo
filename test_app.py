import os
import unittest
from unittest.mock import patch

import app as app_module


class AIProviderTests(unittest.TestCase):
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

    def test_no_provider_is_configured(self):
        with patch.dict(os.environ, {
            "GEMINI_API_KEY": "",
            "GROQ_API_KEY": "",
            "OPENAI_API_KEY": "",
        }, clear=False):
            self.assertFalse(app_module.ai_is_configured())

    def test_status_route_works_without_api_keys(self):
        with patch.dict(os.environ, {
            "GEMINI_API_KEY": "",
            "GROQ_API_KEY": "",
            "OPENAI_API_KEY": "",
        }, clear=False):
            response = self.client.get("/api/status")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["status"], "ok")

    def test_call_ai_without_provider_fails_cleanly(self):
        with patch.dict(os.environ, {
            "GEMINI_API_KEY": "",
            "GROQ_API_KEY": "",
            "OPENAI_API_KEY": "",
        }, clear=False):
            with self.assertRaisesRegex(
                RuntimeError, "No AI provider is configured"
            ):
                app_module.call_ai("Hello")

    def test_gemini_missing_key_does_not_make_request(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": ""}):
            with patch.object(
                app_module.urllib.request,
                "urlopen",
                side_effect=AssertionError("Unexpected network request"),
            ) as mocked_urlopen:
                with self.assertRaisesRegex(
                    RuntimeError, "GEMINI_API_KEY is not configured"
                ):
                    app_module.call_gemini("Hello")
                mocked_urlopen.assert_not_called()

    def test_call_ai_falls_back_to_groq(self):
        with patch.dict(os.environ, {
            "GEMINI_API_KEY": "test-gemini-key",
            "GROQ_API_KEY": "test-groq-key",
            "OPENAI_API_KEY": "",
        }, clear=False):
            with patch.object(
                app_module, "call_gemini",
                side_effect=RuntimeError("simulated Gemini failure"),
            ), patch.object(
                app_module, "call_groq", return_value="Groq test reply"
            ) as groq_mock:
                result = app_module.call_ai("Hello")
                self.assertEqual(result, "Groq test reply")
                groq_mock.assert_called_once_with("Hello")


    def test_call_ai_retries_temporary_provider_error_once(self):
        with patch.dict(os.environ, {
            "GEMINI_API_KEY": "test-gemini-key",
            "GROQ_API_KEY": "test-groq-key",
            "OPENAI_API_KEY": "",
        }, clear=False):
            with patch.object(
                app_module,
                "call_gemini",
                side_effect=[
                    TimeoutError("temporary timeout"),
                    "Gemini recovered",
                ],
            ) as gemini_mock, patch.object(
                app_module, "call_groq", return_value="Groq fallback"
            ) as groq_mock, patch.object(
                app_module.time, "sleep"
            ) as sleep_mock:
                result = app_module.call_ai("Hello")

        self.assertEqual(result, "Gemini recovered")
        self.assertEqual(gemini_mock.call_count, 2)
        groq_mock.assert_not_called()
        sleep_mock.assert_called_once_with(1)

    def test_call_ai_does_not_retry_http_403_before_fallback(self):
        from urllib.error import HTTPError

        forbidden = HTTPError(
            url="https://example.invalid",
            code=403,
            msg="Forbidden",
            hdrs=None,
            fp=None,
        )

        with patch.dict(os.environ, {
            "GEMINI_API_KEY": "test-gemini-key",
            "GROQ_API_KEY": "test-groq-key",
            "OPENAI_API_KEY": "",
        }, clear=False):
            with patch.object(
                app_module, "call_gemini", side_effect=forbidden
            ) as gemini_mock, patch.object(
                app_module, "call_groq", return_value="Groq fallback"
            ) as groq_mock:
                result = app_module.call_ai("Hello")

        self.assertEqual(result, "Groq fallback")
        gemini_mock.assert_called_once_with("Hello")
        groq_mock.assert_called_once_with("Hello")


if __name__ == "__main__":
    unittest.main(verbosity=2)
