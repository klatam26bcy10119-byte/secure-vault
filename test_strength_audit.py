import unittest
from datetime import datetime, timedelta, timezone

from securevault import strength as s
from securevault.audit import run_audit
from securevault.models import Entry


class StrengthTests(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        self.assertEqual(s.check_strength("password").score, 0)
        self.assertEqual(s.check_strength("PASSWORD").score, 0)

    def test_short_password_capped(self):
        self.assertLessEqual(s.check_strength("aB3$").score, 1)

    def test_strong_password(self):
        self.assertGreaterEqual(s.check_strength("v7#Lq!9xT@2mZpR4").score, 3)

    def test_repeat_and_sequence_detection(self):
        self.assertTrue(s.has_repeats("xaaay"))
        self.assertFalse(s.has_repeats("xayay"))
        self.assertTrue(s.has_sequence("ab1234cd"))
        self.assertTrue(s.has_sequence("zyxw"))
        self.assertFalse(s.has_sequence("a1c3e5"))

    def test_entropy_grows_with_length(self):
        self.assertGreater(s.estimate_entropy("aaaaaaaaaaaa"), s.estimate_entropy("aaaaaa"))
        self.assertEqual(s.estimate_entropy(""), 0.0)


class AuditTests(unittest.TestCase):
    def test_detects_weak_reused_and_old(self):
        old_date = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat(timespec="seconds")
        entries = [
            Entry("A", "u", "password"),
            Entry("B", "u", "v7#Lq!9xT@2mZpR4"),
            Entry("C", "u", "v7#Lq!9xT@2mZpR4"),
            Entry("D", "u", "Zk8&nW2!pQ5#tY1x", password_changed_at=old_date),
        ]
        report = run_audit(entries)
        self.assertEqual([e.site for e in report.weak], ["A"])
        self.assertEqual(len(report.reused), 1)
        self.assertEqual({e.site for e in report.reused[0]}, {"B", "C"})
        self.assertEqual([e.site for e in report.old], ["D"])
        self.assertEqual(report.health_score, 0)

    def test_clean_vault_scores_100(self):
        self.assertEqual(run_audit([Entry("A", "u", "v7#Lq!9xT@2mZpR4")]).health_score, 100)
        self.assertEqual(run_audit([]).health_score, 100)


if __name__ == "__main__":
    unittest.main()
