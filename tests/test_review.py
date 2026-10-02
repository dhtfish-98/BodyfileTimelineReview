import unittest
from bodyfiletimelinereview import inspect

D = b"0|/synthetic/private|5-128-1|-rw-r--r--|1000|1000|42|100|200|100|0\n"


class Tests(unittest.TestCase):
    def test_timeline(self):
        r = inspect(D)
        self.assertEqual(r["status"], "PASS")
        self.assertEqual([e["time_unix"] for e in r["timeline"]], ["100", "200"])
        self.assertEqual(r["timeline"][0]["events"], "ac")

    def test_fraction_negative(self):
        self.assertEqual(
            inspect(D.replace(b"100|200|100|0", b"-1.2|200.1|0|0"))["status"], "PASS"
        )

    def test_multiple(self):
        self.assertEqual(
            inspect(D + D.replace(b"|5-128-1|", b"|6|"))["record_count"], 2
        )

    def test_private(self):
        self.assertNotIn("private", str(inspect(D)))

    def test_fields(self):
        self.assertEqual(inspect(D.replace(b"42|", b"42|x|"))["status"], "FAIL")

    def test_mode(self):
        self.assertEqual(
            inspect(D.replace(b"-rw-r--r--", b"nonsense"))["status"], "FAIL"
        )

    def test_numbers(self):
        for old, new in [
            (b"42", b"-1"),
            (b"100|200", b"nan|200"),
            (b"42", b"999999999999999999999999"),
        ]:
            self.assertEqual(inspect(D.replace(old, new))["status"], "FAIL")

    def test_conflict(self):
        self.assertEqual(inspect(D + D.replace(b"|42|", b"|43|"))["status"], "FAIL")

    def test_utf8(self):
        self.assertEqual(inspect(b"\xff")["status"], "FAIL")

    def test_empty(self):
        self.assertEqual(inspect(b"")["status"], "FAIL")

    def test_long_numeric(self):
        self.assertEqual(
            inspect(D.replace(b"|42|", b"|" + b"9" * 5000 + b"|"))["status"], "FAIL"
        )

    def test_tsk_extended_mode_and_permission_positions(self):
        for mode in (b"r/rrwxrwxrwx", b"d/drwxr-xr-x", b"-/----------", b"-rwsr-Sr-T", b"v/v---------"):
            self.assertEqual(inspect(D.replace(b"-rw-r--r--", mode))["status"], "PASS", mode)
        for mode in (b"rxxxxxxxxx", b"rrrrrrrrrr", b"-rwtr--r--", b"r/rrrrrrrrr"):
            self.assertEqual(inspect(D.replace(b"-rw-r--r--", mode))["status"], "FAIL", mode)

    def test_comments_blank_lines_and_explicit_newlines(self):
        report = inspect(b"# generated bodyfile\r\n\r\n" + D.replace(b"\n", b"\r\n"))
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["records"][0]["line"], 3)
        self.assertEqual(inspect(b"# comment only\n\n")["status"], "FAIL")
        self.assertEqual(inspect(D.rstrip(b"\n") + b"\v" + D)["status"], "FAIL")
