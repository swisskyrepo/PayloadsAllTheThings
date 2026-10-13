#!/usr/bin/env python3
# coding=utf-8
import os
import subprocess
import sys
import unittest

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
IP_SCRIPT = os.path.join(SCRIPT_DIR, "ip.py")

class TestSSRFIPEncoding(unittest.TestCase):
    def test_no_syntax_warnings(self):
        """ip.py must compile and execute without raising SyntaxWarning (e.g. invalid escape sequence)."""
        res = subprocess.run(
            [sys.executable, "-W", "error::SyntaxWarning", IP_SCRIPT],
            capture_output=True,
            text=True,
        )
        self.assertNotIn(
            "SyntaxWarning",
            res.stderr,
            f"SyntaxWarning encountered:\n{res.stderr}",
        )
        self.assertNotIn(
            "SyntaxError: invalid escape sequence",
            res.stderr,
            f"Invalid escape sequence encountered:\n{res.stderr}",
        )

    def test_reproduce_unicode_encode_error_stdout(self):
        """ip.py must not crash with UnicodeEncodeError when stdout uses a non-UTF-8 encoding like cp1252."""
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "cp1252:strict"
        res = subprocess.run(
            [sys.executable, IP_SCRIPT, "169.254.169.254", "80", "www.google.com"],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(
            res.returncode,
            0,
            f"Script crashed with exit code {res.returncode}:\nStdout:\n{res.stdout}\nStderr:\n{res.stderr}",
        )
        self.assertNotIn("UnicodeEncodeError", res.stderr)

    def test_reproduce_unicode_encode_error_export(self):
        """ip.py must successfully export Unicode characters to file without UnicodeEncodeError."""
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        # Run export
        res = subprocess.run(
            [sys.executable, IP_SCRIPT, "169.254.169.254", "80", "www.google.com", "export"],
            capture_output=True,
            text=True,
            cwd=SCRIPT_DIR,
            env=env,
        )
        self.assertEqual(
            res.returncode,
            0,
            f"Export failed with code {res.returncode}:\n{res.stderr}",
        )
        self.assertNotIn("UnicodeEncodeError", res.stderr)

        # Locate exported file
        export_files = [f for f in os.listdir(SCRIPT_DIR) if f.startswith("export-169.254.169.254-") and f.endswith(".txt")]
        self.assertTrue(len(export_files) > 0, "Export file was not generated")
        export_path = os.path.join(SCRIPT_DIR, export_files[0])
        try:
            with open(export_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("。", content)
            self.assertIn("｡", content)
        finally:
            if os.path.exists(export_path):
                os.remove(export_path)

if __name__ == "__main__":
    unittest.main()
