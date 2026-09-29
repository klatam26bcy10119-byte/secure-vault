import unittest

from securevault import crypto_utils as cu
from securevault.exceptions import DecryptionError
from tests.helpers import FAST_KDF


class CryptoTests(unittest.TestCase):
    def test_round_trip(self):
        key = cu.derive_key("pw12345678", cu.generate_salt(), FAST_KDF)
        token = cu.encrypt(key, b"secret data")
        self.assertNotIn(b"secret data", token)
        self.assertEqual(cu.decrypt(key, token), b"secret data")

    def test_same_inputs_give_same_key(self):
        salt = cu.generate_salt()
        self.assertEqual(cu.derive_key("abc", salt, FAST_KDF), cu.derive_key("abc", salt, FAST_KDF))

    def test_different_salt_gives_different_key(self):
        a = cu.derive_key("abc", cu.generate_salt(), FAST_KDF)
        b = cu.derive_key("abc", cu.generate_salt(), FAST_KDF)
        self.assertNotEqual(a, b)

    def test_wrong_key_fails(self):
        salt = cu.generate_salt()
        token = cu.encrypt(cu.derive_key("right", salt, FAST_KDF), b"x")
        with self.assertRaises(DecryptionError):
            cu.decrypt(cu.derive_key("wrong", salt, FAST_KDF), token)

    def test_tampered_token_fails(self):
        key = cu.derive_key("pw", cu.generate_salt(), FAST_KDF)
        token = bytearray(cu.encrypt(key, b"data"))
        token[-5] ^= 0x01
        with self.assertRaises(DecryptionError):
            cu.decrypt(key, bytes(token))


if __name__ == "__main__":
    unittest.main()
