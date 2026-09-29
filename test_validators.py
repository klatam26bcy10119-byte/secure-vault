import unittest

from securevault.exceptions import ValidationError
from securevault import validators as v


class ValidatorTests(unittest.TestCase):
    def test_required_trims_and_rejects_empty(self):
        self.assertEqual(v.validate_required("  hi  ", "F"), "hi")
        with self.assertRaises(ValidationError):
            v.validate_required("   ", "F")
        with self.assertRaises(ValidationError):
            v.validate_required("x" * 101, "F")

    def test_master_password_rules(self):
        self.assertEqual(v.validate_master_password("Correct-Horse9"), "Correct-Horse9")
        for bad in ("short1", "onlyletterslong", "1234567890123"):
            with self.assertRaises(ValidationError):
                v.validate_master_password(bad)

    def test_int_range(self):
        self.assertEqual(v.validate_int_range(" 12 ", 8, 64), 12)
        for bad in ("x", "7", "65", ""):
            with self.assertRaises(ValidationError):
                v.validate_int_range(bad, 8, 64)


if __name__ == "__main__":
    unittest.main()
