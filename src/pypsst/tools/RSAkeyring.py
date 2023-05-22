from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from typing import Union
from .utils import Utils
import os


class RsaKeyring:

    def __init__(self, key_file : Union[None, str]=None) -> ...:
        """
        Initialize the RSA tools.
        
        Parameters
        ----------
        key_file : str, optional
            The file to read the key from. If None, a new key will be generated.
        """
        if not isinstance(key_file, (str, type(None))):
            raise TypeError('The key_file must be a string or None, not {}'.format(type(key_file)))
        
        if key_file is not None:
            self._key_pair = self.from_key(key_file)
        else:
            self._key_pair = self.generate_keypair()

    @property
    def public_key_string(self) -> str:
        """Get the public key string."""
        return self._key_pair.public_key().exportKey('PEM').decode('utf-8')

    @property
    def public_key(self) -> bytes:
        """Get the public key."""
        return self._key_pair.public_key().exportKey('PEM')

    def generate_keypair(self) -> ...:
        """Generate a new RSA keypair."""
        return RSA.generate(2048)

    def from_key(self, file : str) -> ...:
        """
        Read the RSA key from a file.
        
        Parameters
        ----------
        file : str
            The file to read the key from.

        Raises
        ------
        TypeError
            If the file is not a string.
        FileNotFoundError
            If the file does not exist.
        ValueError
            If the key is not a private key.
        """
        if not isinstance(file, str):
            raise TypeError('The file must be a string, not {}'.format(type(file)))
        
        # Check if the file exists
        if not Utils.file_exists(file):
            raise FileNotFoundError('The file does not exist.')
        
        key = ''
        with open(file, 'r') as keyfile:
            key = RSA.import_key(keyfile.read())

        # Verify that the key is a private key
        if not key.has_private():
            raise ValueError('The key is not a private key.')
        return key

    def sign(self, data : Union[bytes, dict]) -> bytes:
        """
        Sign the data.
        
        Parameters
        ----------
        data : bytes or dict
            The data to sign. If dict, it will be converted to bytes. All
            values in the dict should either be bytes or str.
        
        Returns
        -------
        bytes
            The signature.
        """
        if not isinstance(data, (bytes, dict)):
            raise TypeError('The data must be bytes, not {}'.format(type(data)))
        if isinstance(data, dict):
            # Convert the dict to bytes
            data = str(data).encode()

        data_hash = Utils.hash_data(data, finalize=False) # Hash the given data
        # Create an object that can sign the data with the RSA keypair
        signature_scheme_obj = PKCS1_v1_5.new(self._key_pair)
        signature = signature_scheme_obj.sign(data_hash) # Sign the data hash with the RSA keypair
        return signature.hex().encode()

    @staticmethod
    def signature_valid(data : bytes, signature : bytes, 
            public_key : bytes) -> bool:
        """
        Check if the signed data is valid.
        
        Parameters
        ----------
        data : bytes
            The data to check.
        signature : bytes
            The signature to check.
        public_key_string : str
            The public key to check the signature with.
        
        Returns
        -------
        bool
            True if the signature is valid, False otherwise.
        """
        if not isinstance(data, bytes):
            raise TypeError('The data must be bytes, not {}'.format(type(data)))
        if not isinstance(signature, bytes):
            raise TypeError('The signature must be bytes, not {}'.format(type(signature)))
        if not isinstance(public_key, bytes):
            raise TypeError('The public_key must be bytes, not {}'.format(type(public_key)))    
        
        data_hash = Utils.hash_data(data, finalize=False)  # Create the data hash for reference
        public_key = RSA.importKey(public_key)  # Import the public key into the RSA object
        signature_scheme_obj = PKCS1_v1_5.new(public_key)  # Create the signature scheme for validation

        # Check if when decrypting the data the datahash is recovered
        signature = bytes.fromhex(signature.decode())
        signature_valid = signature_scheme_obj.verify(data_hash, signature)
        return signature_valid
    
    def encrypt(self, data : bytes, receiver_public_key : bytes) -> bytes:
        """
        Encrypt the data.

        The data is encrypted using AES in EAX mode. The AES key is encrypted
        using RSA in OAEP mode. The AES nonce and tag are appended to the
        encrypted data.
        
        Parameters
        ----------
        data : bytes
            The data to encrypt.
        receiver_public_key : bytes
            The public key of the receiver.
        
        Returns
        -------
        tuple
            The encrypted data, nonce, tag, and encrypted AES key.
        """
        if not isinstance(data, bytes):
            raise TypeError('The data must be bytes, not {}'.format(type(data)))
        if not isinstance(receiver_public_key, bytes):
            raise TypeError('The receiver_public_key must be bytes, not {}'.format(type(receiver_public_key)))

        recipient_key = RSA.importKey(receiver_public_key)
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        return enc_session_key, cipher_aes.nonce, tag, ciphertext
    
    def decrypt(self, data : tuple) -> bytes:
        """
        Decrypt the data.

        The data is decrypted using AES in EAX mode. The AES key is decrypted
        using RSA in OAEP mode.
        
        Parameters
        ----------
        data : tuple
            The encrypted data, nonce, tag, and encrypted AES key.
        
        Returns
        -------
        bytes
            The decrypted data.

        Raises
        ------
        TypeError
            If the data is not a tuple or the content is not bytes.
        ValueError
            If the data is not a tuple of length 4.
        """
        if not isinstance(data, tuple):
            raise TypeError('The data must be a tuple, not {}'.format(type(data)))
        if len(data) != 4:
            raise ValueError('The data must be a tuple of length 4, not {}'.format(len(data)))
        for cnt, i in enumerate(data):
            if not isinstance(i, bytes):
                raise TypeError('The data[{}] must be bytes, not {}'.format(cnt, type(i)))
        
        enc_session_key, nonce, tag, ciphertext = data
        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(self._key_pair)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data


