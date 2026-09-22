"""The 10-minute demo stays local and prints both faces."""

import io
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from tenaille import PRODUCT, TAGLINE
from tenaille.__main__ import main
from tenaille.harbngr import run_starter_checks
from tenaille.harbngr.recon import load_inventory
from tenaille.mcp.server_stub import describe_tools, serve
from tenaille.paths import DEFAULT_INVENTORY, ROOT, STARTER_CHECKS


class DemoTests(unittest.TestCase):
    def test_demo_exits_zero_and_names_both_faces(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(["demo"])
        text = buffer.getvalue()
        self.assertEqual(code, 0)
        self.assertIn(PRODUCT, text)
        self.assertIn(TAGLINE, text)
        self.assertIn("ten-AY", text)
        self.assertIn("CVINFERNO", text)
        self.assertIn("CVBASTION", text)
        self.assertIn("CVE-2024-6387", text)
        self.assertIn("CVE-2023-38408", text)
        self.assertIn("version_match", text)
        self.assertNotIn("exploited", text.lower())

    def test_lookup_recon_and_assess_use_fixtures(self):
        lookup = io.StringIO()
        with redirect_stdout(lookup):
            self.assertEqual(main(["lookup", "CVE-2024-6387"]), 0)
        self.assertIn("not a live lookup", lookup.getvalue())

        recon = io.StringIO()
        with redirect_stdout(recon):
            self.assertEqual(
                main(["recon", "--inventory", "examples/lab-web-01.json"]),
                0,
            )
        self.assertIn("No SSH session was opened.", recon.getvalue())
        self.assertIn("[pass] sshd-version", recon.getvalue())

        red = io.StringIO()
        with redirect_stdout(red):
            self.assertEqual(
                main(["assess", "--inventory", "examples/lab-web-01.json", "--mode", "red"]),
                0,
            )
        self.assertIn("CVINFERNO", red.getvalue())
        self.assertNotIn("CVBASTION", red.getvalue())

        blue = io.StringIO()
        with redirect_stdout(blue):
            self.assertEqual(main(["assess", "--mode", "blue"]), 0)
        self.assertIn("CVBASTION", blue.getvalue())
        self.assertNotIn("CVINFERNO", blue.getvalue())

    def test_live_flags_fail_closed(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code = main(["lookup", "CVE-2024-6387", "--live"])
        self.assertEqual(code, 2)
        self.assertIn("Live intel is not enabled", err.getvalue())

        err = io.StringIO()
        with redirect_stderr(err):
            code = main(["recon", "--inventory", "examples/lab-web-01.json", "--live"])
        self.assertEqual(code, 2)
        self.assertIn("Live SSH", err.getvalue())

    def test_unknown_cve_does_not_fetch(self):
        err = io.StringIO()
        with redirect_stderr(err):
            code = main(["lookup", "CVE-1999-0001"])
        self.assertEqual(code, 2)
        self.assertIn("No local fixture", err.getvalue())

    def test_non_fixture_inventory_is_refused(self):
        stray = ROOT / "tests" / "_not_a_fixture.json"
        stray.write_text('{"host": {"id": "real"}}', encoding="utf-8")
        try:
            err = io.StringIO()
            with redirect_stderr(err):
                code = main(["recon", "--inventory", str(stray)])
            self.assertEqual(code, 2)
            self.assertIn("synthetic lab", err.getvalue())
        finally:
            stray.unlink(missing_ok=True)

    def test_starter_pack_size_and_windows_fixture(self):
        checks = list(Path(STARTER_CHECKS).glob("*.json"))
        self.assertGreaterEqual(len(checks), 8)
        self.assertLessEqual(len(checks), 12)
        inventory = load_inventory(DEFAULT_INVENTORY)
        results = run_starter_checks(inventory)
        self.assertTrue(all(item["status"] == "pass" for item in results))

    def test_mcp_stub_does_not_serve(self):
        names = {item["name"] for item in describe_tools()}
        self.assertEqual(
            names,
            {"lookup_cve", "assess_inventory", "get_red_brief", "get_blue_brief"},
        )
        with self.assertRaises(RuntimeError):
            serve()


if __name__ == "__main__":
    unittest.main()
