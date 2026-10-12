
import unittest

from security import (
    encrypt_data,
    decrypt_data,
    calculate_sha256,
    check_password_strength,
)


class SecureVaultTests(unittest.TestCase):

    def test_encryption_and_decryption(self):
        original = b"SecureVault CNS Project"
        encrypted = encrypt_data(original, "Example-Strong-2026!")
        decrypted = decrypt_data(encrypted, "Example-Strong-2026!")
        self.assertEqual(original, decrypted)

    def test_wrong_password(self):
        encrypted = encrypt_data(b"Secret message", "Correct-Password-2026!")

        with self.assertRaises(ValueError):
            decrypt_data(encrypted, "Wrong-Password")

    def test_sha256(self):
        self.assertEqual(
            calculate_sha256(b"hello"),
            calculate_sha256(b"hello")
        )

    def test_modified_data_hash(self):
        self.assertNotEqual(
            calculate_sha256(b"hello"),
            calculate_sha256(b"hello!")
        )

    def test_empty_password(self):
        result = check_password_strength("")
        self.assertEqual(result["strength"], "Empty")


if __name__ == "__main__":
    unittest.main()
