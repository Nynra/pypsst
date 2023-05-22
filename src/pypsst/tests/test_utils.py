import unittest
from pypsst import Utils
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA256, SHA512
from Crypto.Cipher import AES
import os


class TestUtils(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> ...:
        # Generate an RSA keypair
        cls.rsa_keypair = RSA.generate(2048)

    def test_get_timestamp(self) -> ...:
        # Get the timestamp
        timestamp = Utils.get_timestamp()
        self.assertIsInstance(timestamp, bytes)
        self.assertGreater(float(timestamp), 0)

    def test_get_id(self) -> ...:
        # Get the id
        id = Utils.get_id()
        self.assertIsInstance(id, bytes)
        self.assertEqual(len(id), 32)

    def test_generate_rsa_keypair(self) -> ...:
        # Generate a RSA keypair
        keypair = Utils.generate_rsa_keypair()
        self.assertIsInstance(keypair, bytes)

        # Try loading the keypair
        new_keypair = RSA.import_key(keypair)

        # Check if the keys match
        self.assertEqual(keypair, new_keypair.export_key(format="PEM"))

    def test_generate_ecc_key(self) -> ...:
        # Generate a ECC key
        key = Utils.generate_ecc_key()
        self.assertIsInstance(key, bytes)

        # Try loading the key
        new_key = ECC.import_key(key)

        # Check if the keys match
        self.assertEqual(key, new_key.export_key(format="PEM").encode())

    def test_sha256(self) -> ...:
        # Hash some data with finalize
        data = b'Hello World'
        expected = SHA256.new(data=data)
        expected = expected.hexdigest().encode()

        result = Utils.hash_data(data, finalize=True, type="sha256")
        self.assertEqual(result, expected)

        # Hash some data without finalize
        expected = SHA256.new(data=data)

        result = Utils.hash_data(data, finalize=False, type="sha256")
        self.assertIsInstance(result, SHA256.SHA256Hash)
        self.assertEqual(result.digest(), expected.digest())

    def test_sha512(self) -> ...:
        # Hash some data with finalize
        data = b'Hello World'
        expected = SHA512.new(data=data)
        expected = expected.hexdigest().encode()

        result = Utils.hash_data(data, finalize=True, type="sha512")
        self.assertEqual(result, expected)

        # Hash some data without finalize
        expected = SHA512.new(data=data)

        result = Utils.hash_data(data, finalize=False, type="sha512")
        self.assertIsInstance(result, SHA512.SHA512Hash)
        self.assertEqual(result.digest(), expected.digest())

    def test_file_exists(self) -> ...:
        # Test if the file exists
        self.assertTrue(Utils.file_exists(__file__))

        # Test if the file does not exist
        self.assertFalse(Utils.file_exists("test.txt"))

        # Create a file in the current directory
        with open("test.txt", "w") as f:
            f.write("Hello World")
        
        # Test if the file exists
        self.assertTrue(Utils.file_exists("test.txt"))
        os.remove("test.txt")

    def test_dir_exists(self) -> ...:
        # Test if the directory exists
        dir_path = os.path.dirname(__file__)
        self.assertTrue(Utils.dir_exists(dir_path))

        # Test if the directory does not exist
        self.assertFalse(Utils.dir_exists("test"))

    def test_encrypt_and_decrypt(self) -> ...:
        # Decrypt some data
        data = b'Hello World'
        password = 'password'

        pass_hash = Utils.hash_data(password.encode(), finalize=False).digest()
        cypher = AES.new(pass_hash, AES.MODE_EAX)
        ctekst, tag = cypher.encrypt_and_digest(data)
        expected = b"".join([cypher.nonce, tag, ctekst])

        result = Utils.decrypt(expected, password)
        self.assertEqual(result, data)

        encrypted = Utils.encrypt(data, password)
        result = Utils.decrypt(encrypted, password)
        self.assertEqual(result, data)

    def test_rsa_public_key_valid(self):
        # Test if the public key is valid
        public_key = self.rsa_keypair.publickey().export_key(format="PEM")
        self.assertTrue(Utils.rsa_key_valid(public_key, key_type='public'))

        # Test if the public key is not valid
        self.assertFalse(Utils.rsa_key_valid(b"Hello World", key_type='public'))

    def test_rsa_private_key_valid(self):
        # Test if the private key is valid
        private_key = self.rsa_keypair.export_key(format="PEM")
        self.assertTrue(Utils.rsa_key_valid(private_key, key_type='private'))

        # Test if the private key is not valid
        self.assertFalse(Utils.rsa_key_valid(b"Hello World", key_type='private'))

        

