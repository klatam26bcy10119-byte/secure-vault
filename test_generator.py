import string
import unittest

from securevault import generator as g
from securevault.exceptions import ValidationError


class GeneratorTests(unittest.TestCase):
    def test_length(self):
        for n in (8, 16, 64):
            self.assertEqual(len(g.generate_password(n)), n)

    def test_contains_every_selected_type(self):
        for _ in range(50):
            pw = g.generate_password(8)
            self.assertTrue(any(c in string.ascii_lowercase for c in pw))
            self.assertTrue(any(c in string.ascii_uppercase for c in pw))
            self.assertTrue(any(c in string.digits for c in pw))
            self.assertTrue(any(c in g.SYMBOLS for c in pw))

    def test_no_symbols(self):
        self.assertTrue(all(c.isalnum() for c in g.generate_password(40, use_symbols=False)))

    def test_exclude_ambiguous(self):
        for _ in range(50):
            self.assertFalse(set(g.generate_password(30, exclude_ambiguous=True)) & g.AMBIGUOUS)

    def test_invalid_length(self):
        for bad in (3, 65, "abc"):
            with self.assertRaises(ValidationError):
                g.generate_password(bad)

    def test_no_character_type_selected(self):
        with self.assertRaises(ValidationError):
            g.generate_password(12, False, False, False, False)

    def test_passwords_are_unique(self):
        self.assertEqual(len({g.generate_password(16) for _ in range(200)}), 200)


if __name__ == "__main__":
    unittest.main()
