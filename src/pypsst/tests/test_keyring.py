import sys, os
#Following lines are for assigning parent directory dynamically.
dir_path = os.path.dirname(os.path.realpath(__file__))
parent_dir_path = os.path.abspath(os.path.join(dir_path, os.pardir))
sys.path.insert(0, parent_dir_path)

import unittest
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import PKCS1_v1_5, eddsa
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from tools import RsaKeyring, EccKeyring
from tools.utils import Utils


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
        expected = expected.hex().encode()

        self.assertEqual(signature, expected)

    def test_verify_signature(self):
        # Sign the message
        message = b"Hello World"
        data_hash = Utils.hash_data(message, finalize=False)
        signature_scheme_obj = PKCS1_v1_5.new(self.genesis_key)
        signature = signature_scheme_obj.sign(data_hash)
        signature = signature.hex().encode()

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

    def test_encrypt(self):
        # Create a keypair for the recipient
        recipient_key = RSA.generate(2048)
        recipient_public_key = recipient_key.public_key().exportKey("PEM")

        # Encrypt the message
        message = b"Hello World"
        encrypted_message = self.wallet.encrypt(message, recipient_public_key)

        # Decrypt the message
        enc_session_key, nonce, tag, ciphertext = encrypted_message
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)

        self.assertEqual(data, message)

    def test_decrypt(self):
        # Encrypt the message
        message = b"Hello World"
        receiver_key = RSA.importKey(self.wallet.public_key)
        session_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(receiver_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message)
        encrypted_message = (enc_session_key, cipher_aes.nonce, tag, ciphertext)

        # Decrypt the message
        decrypted_message = self.wallet.decrypt(encrypted_message)

        self.assertEqual(decrypted_message, message)


class TestEccKeyring(unittest.TestCase):
    # MAKE SURE THE KEY EXISTS, OTHERWISE THE TESTS WILL FAIL WITHOUT ERROR
    dir_path = os.path.dirname(os.path.realpath(__file__))
    private_key_file = dir_path + "/test_keys/test_ecc_private_key.pem"

    @classmethod
    def setUpClass(cls):
        # Load the genesis private key
        with open(cls.private_key_file, "rt") as f:
            cls.genesis_key = ECC.import_key(f.read())

        cls.public_key = cls.genesis_key.public_key().export_key(format="PEM").encode()

    def setUp(self):
        self.wallet = EccKeyring(key_file=self.private_key_file)

    def test_load_from_key(self):
        pk = self.wallet.public_key
        self.assertIsInstance(pk, bytes)
        self.assertEqual(pk, self.public_key)

    def test_sign(self):
        message = b"Hello World"
        signature = self.wallet.sign(message)

        # Verify the signature
        data_hash = Utils.hash_data(message, finalize=False, type="sha512")
        signature_scheme_obj = eddsa.new(self.genesis_key, mode='rfc8032')
        expected = signature_scheme_obj.sign(data_hash)

        self.assertEqual(signature, expected)

    def test_verify_signature(self):
        # Sign the message
        message = b"Hello World"
        data_hash = Utils.hash_data(message, finalize=False, type="sha512")
        signature_scheme_obj = eddsa.new(self.genesis_key, mode='rfc8032')
        signature = signature_scheme_obj.sign(data_hash)

        self.assertTrue(
            self.wallet.signature_valid(message, signature, self.public_key)
        )

    def test_get_public_key_string(self):
        pk = self.wallet.public_key_string
        self.assertEqual(pk, self.public_key.decode())
        self.assertIsInstance(pk, str)

    def test_get_public_key_bytes(self):
        pk = self.wallet.public_key
        self.assertEqual(pk, self.public_key)
        self.assertIsInstance(pk, bytes)
