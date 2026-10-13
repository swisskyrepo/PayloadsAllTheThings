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
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        self.assertEqual(
            res.returncode,
            0,
            f"Script crashed with exit code {res.returncode}:\nStderr:\n{res.stderr}",
        )
        self.assertNotIn("UnicodeEncodeError", res.stderr)
        self.assertIn("Abusing", res.stdout)

    def test_stdout_ascii_encoding_resilience(self):
        """ip.py must not crash with UnicodeEncodeError when stdout uses pure ascii."""
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "ascii:strict"
        res = subprocess.run(
            [sys.executable, IP_SCRIPT, "169.254.169.254", "80", "www.google.com"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        self.assertEqual(res.returncode, 0, f"Script crashed on ASCII stdout: {res.stderr}")
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
            encoding="utf-8",
            errors="replace",
            cwd=SCRIPT_DIR,
            env=env,
        )
        self.assertEqual(
            res.returncode,
            0,
            f"Export failed with code {res.returncode}:\n{res.stderr}",
        )
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

    def test_two_digit_enclosed_alphanumerics(self):
        """ip.py should map two-digit octets (10..20) to their corresponding enclosed characters (e.g. ⑩)."""
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        res = subprocess.run(
            [sys.executable, IP_SCRIPT, "10.10.10.10", "80", "www.google.com"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=env,
        )
        self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}")
        # The octet '10' has dedicated glyph '⑩' in EnclosedAlphanumericsData
        self.assertTrue(
            any("⑩" in line for line in res.stdout.splitlines() if "Abusing Enclosed Alphanumerics" in line),
            f"Expected '⑩' for octet 10, got:\n{res.stdout}",
        )

if __name__ == "__main__":
    unittest.main()

