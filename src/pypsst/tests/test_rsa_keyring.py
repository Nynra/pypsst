import unittest
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import PKCS1_v1_5, eddsa
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from pypsst import RsaKeyring, EccKeyring, Utils
import os
import json


class TestRsaKeyring(unittest.TestCase):
    # MAKE SURE THE KEY EXISTS, OTHERWISE THE TESTS WILL FAIL WITHOUT ERROR
    dir_path = os.path.dirname(os.path.realpath(__file__))
    private_key_file = dir_path + "/test_keys/test_rsa_private_key.pem"

    @classmethod
    def setUpClass(cls):
        # Load the genesis private key
        with open(cls.private_key_file, "rb") as f:
            cls.genesis_key = RSA.importKey(f.read())

        cls.public_key = cls.genesis_key.publickey().exportKey("PEM")

    def setUp(self):
        self.wallet = RsaKeyring(key_file=self.private_key_file)

    def test_load_from_key(self):
        self.assertEqual(self.wallet.public_key, self.public_key)

    # # Test sign
    def test_sign(self):
        message = b"Hello World"
        signature = self.wallet.sign(message)

        # Verify the signature
        data_hash = Utils.hash_data(message, finalize=False)
        signature_scheme_obj = PKCS1_v1_5.new(self.genesis_key)
        expected = signature_scheme_obj.sign(data_hash)

        self.assertEqual(signature, expected)

    def test_verify_signature(self):
        # Sign the message
        message = b"Hello World"
        data_hash = Utils.hash_data(message, finalize=False)
        signature_scheme_obj = PKCS1_v1_5.new(self.genesis_key)
        signature = signature_scheme_obj.sign(data_hash)

        self.assertTrue(
            self.wallet.signature_valid(message, signature, self.public_key)
        )

    def test_get_public_key_string(self):
        # Load the genesis_public_key.pem file
        pk = self.wallet.public_key_string
        self.assertEqual(pk, self.public_key.decode())
        self.assertIsInstance(pk, str)

    def test_get_public_key_bytes(self):
        # Load the genesis_public_key.pem file
        pk = self.wallet.public_key
        self.assertEqual(pk, self.public_key)
        self.assertIsInstance(pk, bytes)

    def test_encrypt_decrypt_to_self(self):
        # Encrypt the message
        message = b"Hello World"
        encrypted_message = self.wallet.encrypt(message, self.public_key)

        # Decrypt the message
        decrypted_message = self.wallet.decrypt(encrypted_message)

        self.assertEqual(message, decrypted_message)

    def test_encrypt_decrypt_to_other(self):
        # Create a keypair for the recipient
        recipient = RsaKeyring()

        # Encrypt the message
        message = b"Hello World"
        encrypted_message = self.wallet.encrypt(message, recipient.public_key)

        # Decrypt the message
        decrypted_message = recipient.decrypt(encrypted_message)

        self.assertEqual(message, decrypted_message)

        # Try to decrypt with the wrong key
        with self.assertRaises(ValueError):
            self.wallet.decrypt(encrypted_message)


# class TestEccKeyring(unittest.TestCase):
#     # MAKE SURE THE KEY EXISTS, OTHERWISE THE TESTS WILL FAIL WITHOUT ERROR
#     dir_path = os.path.dirname(os.path.realpath(__file__))
#     private_key_file = dir_path + "/test_keys/test_ecc_private_key.pem"

#     @classmethod
#     def setUpClass(cls):
#         # Load the genesis private key
#         with open(cls.private_key_file, "rt") as f:
#             cls.genesis_key = ECC.import_key(f.read())

#         cls.public_key = cls.genesis_key.public_key().export_key(format="PEM").encode()

#     def setUp(self):
#         self.wallet = EccKeyring(key_file=self.private_key_file)

#     def test_load_from_key(self):
#         pk = self.wallet.public_key
#         self.assertIsInstance(pk, bytes)
#         self.assertEqual(pk, self.public_key)

#     def test_sign(self):
#         message = b"Hello World"
#         signature = self.wallet.sign(message)

#         # Verify the signature
#         data_hash = Utils.hash_data(message, finalize=False, type="sha512")
#         signature_scheme_obj = eddsa.new(self.genesis_key, mode="rfc8032")
#         expected = signature_scheme_obj.sign(data_hash)

#         self.assertEqual(signature, expected)

#     def test_verify_signature(self):
#         # Sign the message
#         message = b"Hello World"
#         data_hash = Utils.hash_data(message, finalize=False, type="sha512")
#         signature_scheme_obj = eddsa.new(self.genesis_key, mode="rfc8032")
#         signature = signature_scheme_obj.sign(data_hash)

#         self.assertTrue(
#             self.wallet.signature_valid(message, signature, self.public_key)
#         )

#     def test_get_public_key_string(self):
#         pk = self.wallet.public_key_string
#         self.assertEqual(pk, self.public_key.decode())
#         self.assertIsInstance(pk, str)

#     def test_get_public_key_bytes(self):
#         pk = self.wallet.public_key
#         self.assertEqual(pk, self.public_key)
#         self.assertIsInstance(pk, bytes)
