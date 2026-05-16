import os
import shutil
import unittest
from datetime import date, timedelta


class TestEndToEndFlow(unittest.TestCase):
    """
    Smoke test for the core product flow:
    client -> request pentest -> admin approve/assign/start -> pentester submit finding.
    """

    @classmethod
    def setUpClass(cls):
        # Import here so we can safely manipulate DB between tests.
        import ptaas_db

        cls.ptaas_db = ptaas_db
        cls.repo_root = os.path.dirname(os.path.dirname(__file__))
        cls.db_path = os.path.join(cls.repo_root, "ptaas.db")
        cls.backup_path = os.path.join(cls.repo_root, "ptaas.db.__bak_test_flow__")

        # Backup DB so tests are repeatable and do not leave data behind.
        if os.path.exists(cls.db_path):
            shutil.copyfile(cls.db_path, cls.backup_path)

        # Ensure schema exists.
        cls.ptaas_db.init_ptaas_db()

        # Ensure baseline users exist for the flow.
        cls.password = "Redcon@2024!"
        cls.admin_email = "admin@redconoffence.com"
        cls.client_email = "client@redconoffence.com"
        cls.pentester_email = "pentester@redconoffence.com"

        def ensure_user(email: str, role: str, name: str, company: str = ""):
            u = cls.ptaas_db.get_user_by_email(email)
            if u:
                return u
            created = cls.ptaas_db.create_user(
                email=email,
                password=cls.password,
                name=name,
                role=role,
                company=company,
            )
            if not created:
                raise RuntimeError(f"Failed to create user {email} ({role})")
            return created

        cls.admin_user = ensure_user(cls.admin_email, "admin", "Admin", "REDCON OFFENCE")
        cls.client_user = ensure_user(cls.client_email, "client", "Client User", "Test Company")
        cls.pentester_user = ensure_user(cls.pentester_email, "pentester", "Pentester", "REDCON OFFENCE")

        # Import Flask app after DB is ready.
        import app as app_module

        cls.app = app_module.app
        cls.app.config["TESTING"] = True

        # Track created records for cleanup (best-effort; DB backup restore is the source of truth).
        cls.created_pentest_ids = []
        cls.created_finding_ids = []

    @classmethod
    def tearDownClass(cls):
        # Best-effort cleanup.
        try:
            conn = cls.ptaas_db.get_db()
            c = conn.cursor()
            for fid in cls.created_finding_ids:
                c.execute("DELETE FROM ptaas_findings WHERE id = ?", (fid,))
            for pid in cls.created_pentest_ids:
                c.execute("DELETE FROM pentest_pentesters WHERE pentest_id = ?", (pid,))
                c.execute("DELETE FROM pentests WHERE id = ?", (pid,))
            conn.commit()
            conn.close()
        except Exception:
            pass

        # Restore DB from backup to guarantee no persistent test data.
        if os.path.exists(cls.backup_path):
            shutil.copyfile(cls.backup_path, cls.db_path)
            try:
                os.remove(cls.backup_path)
            except OSError:
                pass

    def _login(self, client, email: str, password: str):
        res = client.post(
            "/api/auth/login",
            json={"email": email, "password": password},
        )
        self.assertEqual(res.status_code, 200, res.get_data(as_text=True))
        data = res.get_json()
        self.assertTrue(data.get("success"), data)
        return data

    def _logout(self, client):
        res = client.post("/api/auth/logout")
        self.assertEqual(res.status_code, 200, res.get_data(as_text=True))
        data = res.get_json()
        self.assertTrue(data.get("success"), data)

    def test_core_flow_client_to_pentester_submit_finding(self):
        with self.app.test_client() as c:
            # 1) Client logs in and requests a pentest
            self._login(c, self.client_email, self.password)

            start_date = (date.today() + timedelta(days=1)).isoformat()
            end_date = (date.today() + timedelta(days=10)).isoformat()

            req_payload = {
                "title": "E2E Flow Test - Web App",
                "type": "web",
                "priority": "high",
                "scope": "Test scope for e2e flow.",
                "targets": "https://example.com\nhttps://api.example.com",
                "start_date": start_date,
                "end_date": end_date,
                "tech_stack": "Flask, PostgreSQL, Nginx",
                "objectives": "Validate end-to-end flow works.",
                "environment": "production",
                "collaboration": "async",
                "sensitive_data": ["pii", "credentials"],
                "credential_type": "user_pass",
                "credentials_notes": "user: test@example.com\\npass: TestPass123!",
                "notes": "E2E test request",
            }

            res = c.post("/api/client/request-pentest", json=req_payload)
            self.assertEqual(res.status_code, 200, res.get_data(as_text=True))
            body = res.get_json()
            self.assertTrue(body.get("success"), body)
            pentest_id = body["pentest"]["id"]
            self.created_pentest_ids.append(pentest_id)

            self._logout(c)

            # 2) Admin approves, assigns pentester, and starts
            self._login(c, self.admin_email, self.password)

            res = c.post(f"/api/admin/pentest/{pentest_id}/approve")
            self.assertEqual(res.status_code, 200, res.get_data(as_text=True))
            self.assertTrue(res.get_json().get("success"), res.get_json())

            res = c.post(
                f"/api/admin/pentest/{pentest_id}/assign",
                json={"pentester_id": self.pentester_user["id"], "role": "tester"},
            )
            self.assertEqual(res.status_code, 200, res.get_data(as_text=True))
            self.assertTrue(res.get_json().get("success"), res.get_json())

            res = c.post(f"/api/admin/pentest/{pentest_id}/start")
            self.assertEqual(res.status_code, 200, res.get_data(as_text=True))
            self.assertTrue(res.get_json().get("success"), res.get_json())

            self._logout(c)

            # 3) Pentester sees assigned pentest and can submit finding
            self._login(c, self.pentester_email, self.password)

            res = c.get("/api/ptaas/pentests")
            self.assertEqual(res.status_code, 200, res.get_data(as_text=True))
            pentests = res.get_json().get("pentests", [])
            self.assertTrue(any(p["id"] == pentest_id for p in pentests), pentests)

            # Ensure detail endpoint returns status live and includes client-submitted fields.
            res = c.get(f"/api/ptaas/pentest/{pentest_id}")
            self.assertEqual(res.status_code, 200, res.get_data(as_text=True))
            detail = res.get_json()["pentest"]
            self.assertIn(detail["status"].lower(), ("live", "live "), detail["status"])
            # Not all fields are guaranteed in this endpoint across versions, but these should exist.
            self.assertIn("targets", detail)

            finding_payload = {
                "pentest_id": pentest_id,
                "title": "E2E Finding - Test Vulnerability",
                "severity": "high",
                "description": "This is a test finding created by the automated smoke test.",
                "poc": "curl -i https://example.com",
                "impact": "Test impact",
                "recommendation": "Test recommendation",
                "category": "Test",
                "cwe": "CWE-000",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            }

            res = c.post("/api/pentester/finding", json=finding_payload)
            self.assertEqual(res.status_code, 200, res.get_data(as_text=True))
            data = res.get_json()
            self.assertTrue(data.get("success"), data)
            # API returns a finding_id (and not a full finding object)
            finding_id = data["finding_id"]
            self.created_finding_ids.append(finding_id)

            self._logout(c)

            # 4) Client can fetch the finding (access control + linkage check)
            self._login(c, self.client_email, self.password)
            res = c.get(f"/api/client/finding/{finding_id}")
            self.assertEqual(res.status_code, 200, res.get_data(as_text=True))
            fdata = res.get_json().get("finding")
            self.assertIsNotNone(fdata, res.get_json())
            self.assertEqual(fdata["id"], finding_id)


if __name__ == "__main__":
    unittest.main()


