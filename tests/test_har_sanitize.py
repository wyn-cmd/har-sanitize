import importlib.util
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

# Load the module straight from its file so the tests run without installing.
SPEC = importlib.util.spec_from_file_location("har_sanitize", os.path.join(ROOT, "har_sanitize.py"))
har_sanitize = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(har_sanitize)


def build_har():
    # A tiny capture holding one token in every place a token can hide.
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "test", "version": "1"},
            "entries": [
                {
                    "startedDateTime": "2026-01-01T00:00:00.000Z",
                    "time": 120.0,
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/v1/me?access_token=abc123secret&page=2",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer sk_live_abcdefghijkl"},
                            {"name": "Accept", "value": "application/json"},
                        ],
                        "cookies": [{"name": "sid", "value": "cookie-value-here"}],
                        "queryString": [
                            {"name": "access_token", "value": "abc123secret"},
                            {"name": "page", "value": "2"},
                        ],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Set-Cookie", "value": "sid=deadbeef; HttpOnly"}],
                        "cookies": [{"name": "sid", "value": "deadbeef"}],
                        "content": {
                            "size": 180,
                            "mimeType": "application/json",
                            "text": json.dumps({"user": "kim", "api_key": "sk_live_zzzz"}),
                        },
                    },
                },
                {
                    "startedDateTime": "2026-01-01T00:00:01.000Z",
                    "time": 40.0,
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/v1/login",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "cookies": [],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps({"email": "kim@example.com", "password": "hunter2"}),
                        },
                    },
                    "response": {
                        "status": 401,
                        "headers": [],
                        "cookies": [],
                        "content": {"size": 12, "mimeType": "text/plain", "text": "denied"},
                    },
                },
            ],
        }
    }


class RedactionTests(unittest.TestCase):
    def test_headers_and_query_are_redacted(self):
        har = build_har()
        counter = har_sanitize.redact_har(har, har_sanitize.default_options())
        entry = har["log"]["entries"][0]

        header = entry["request"]["headers"][0]
        self.assertEqual(header["value"], har_sanitize.REDACTED)
        # A harmless header keeps its value.
        self.assertEqual(entry["request"]["headers"][1]["value"], "application/json")
        self.assertIn("access_token=%5BREDACTED%5D", entry["request"]["url"])
        self.assertIn("page=2", entry["request"]["url"])
        self.assertNotIn("abc123secret", entry["request"]["url"])
        self.assertEqual(entry["request"]["queryString"][0]["value"], har_sanitize.REDACTED)
        self.assertEqual(entry["request"]["cookies"][0]["value"], har_sanitize.REDACTED)
        self.assertGreater(counter["headers"], 0)

    def test_json_bodies_are_redacted_field_by_field(self):
        har = build_har()
        har_sanitize.redact_har(har, har_sanitize.default_options())
        response_text = har["log"]["entries"][0]["response"]["content"]["text"]
        body = json.loads(response_text)
        self.assertEqual(body["api_key"], har_sanitize.REDACTED)
        self.assertEqual(body["user"], "kim")

        login_text = har["log"]["entries"][1]["request"]["postData"]["text"]
        login = json.loads(login_text)
        self.assertEqual(login["password"], har_sanitize.REDACTED)
        self.assertEqual(login["email"], "kim@example.com")

    def test_check_counts_findings(self):
        har = build_har()
        counter = har_sanitize.redact_har(har, har_sanitize.default_options())
        self.assertGreaterEqual(har_sanitize.total_findings(counter), 5)

    def test_clean_capture_reports_nothing(self):
        har = build_har()
        har_sanitize.redact_har(har, har_sanitize.default_options())
        # A second pass over an already cleaned capture finds nothing new.
        second = har_sanitize.redact_har(har, har_sanitize.default_options())
        self.assertEqual(har_sanitize.total_findings(second), 0)

    def test_drop_content_removes_bodies(self):
        har = build_har()
        options = har_sanitize.default_options()
        options.drop_content = True
        counter = har_sanitize.redact_har(har, options)
        content = har["log"]["entries"][0]["response"]["content"]
        self.assertNotIn("text", content)
        self.assertEqual(content["size"], 0)
        self.assertEqual(counter["content"], 2)
        self.assertEqual(counter["bytes"], 192)

    def test_scrub_emails_is_opt_in(self):
        har = build_har()
        har_sanitize.redact_har(har, har_sanitize.default_options())
        login_text = har["log"]["entries"][1]["request"]["postData"]["text"]
        self.assertIn("kim@example.com", login_text)

        har = build_har()
        options = har_sanitize.default_options()
        options.scrub_emails = True
        har_sanitize.redact_har(har, options)
        login_text = har["log"]["entries"][1]["request"]["postData"]["text"]
        self.assertNotIn("kim@example.com", login_text)

    def test_summary_groups_hosts_and_statuses(self):
        har = build_har()
        data = har_sanitize.summarize(har)
        self.assertEqual(data["entries"], 2)
        self.assertEqual(data["hosts"]["api.example.com"]["requests"], 2)
        self.assertEqual(data["hosts"]["api.example.com"]["errors"], 1)
        self.assertEqual(data["status"]["2xx"], 1)
        self.assertEqual(data["status"]["4xx"], 1)
        self.assertEqual(data["total_bytes"], 192)
        self.assertEqual(data["slowest"][0]["time_ms"], 120.0)

    def test_summary_hides_query_secrets(self):
        # Summary output ends up in tickets, so it must not echo a live token.
        data = har_sanitize.summarize(build_har())
        self.assertNotIn("abc123secret", json.dumps(data))


if __name__ == "__main__":
    unittest.main()
