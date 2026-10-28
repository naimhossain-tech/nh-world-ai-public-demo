import unittest

import app as app_module
from werkzeug.security import generate_password_hash


class OwnerAuthenticationTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        app_module.app.config["OWNER_USERNAME"] = "test-owner"
        app_module.app.config["OWNER_PASSWORD_HASH"] = generate_password_hash(
            "test-only-password"
        )
        self.client = app_module.app.test_client()

    def test_dashboard_redirects_when_logged_out(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_sensitive_api_requires_login(self):
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 401)

    def test_login_rejects_wrong_password(self):
        page = self.client.get("/login")
        self.assertEqual(page.status_code, 200)
        with self.client.session_transaction() as sess:
            token = sess["csrf_token"]

        response = self.client.post("/login", data={
            "csrf_token": token,
            "username": "test-owner",
            "password": "wrong-password",
        })
        self.assertEqual(response.status_code, 401)

    def test_login_and_logout(self):
        self.client.get("/login")
        with self.client.session_transaction() as sess:
            token = sess["csrf_token"]

        response = self.client.post("/login", data={
            "csrf_token": token,
            "username": "test-owner",
            "password": "test-only-password",
        })
        self.assertEqual(response.status_code, 302)

        status = self.client.get("/api/status")
        self.assertEqual(status.status_code, 200)

        with self.client.session_transaction() as sess:
            logout_token = sess["csrf_token"]

        response = self.client.post("/logout", data={
            "csrf_token": logout_token,
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/api/status").status_code, 401)


if __name__ == "__main__":
    unittest.main()
