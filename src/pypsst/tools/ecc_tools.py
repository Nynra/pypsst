from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
from .utils import Utils
from typing import Union
import os


class EccKeyring:
    def __init__(self, key_file: Union[None, str] = None) -> ...:
        """
        Initialize the ECC tools.

        Parameters
        ----------
        key_file : str, optional
            The file to read the key from. If None, a new key will be generated.
        """
        if not isinstance(key_file, (str, type(None))):
            raise TypeError(
                "The key_file must be a string or None, not {}".format(type(key_file))
            )
        if key_file is not None:
            self.from_key(key_file)
        else:
            # Generate a new key if no key file was provided
            self._encryption_keypair = generate_eth_key()

    @property
    def encryption_public_key_string(self) -> str:
        """Get the public key string."""
        # Export the public key from the keypare as a utf-8 string
        return self._encryption_key_pair.public_key.to_hex()

    @property
    def encryption_public_key(self) -> bytes:
        """Get the public key."""
        # Export the public key from the keypare as a utf-8 string
        return self._encryption_key_pair.public_key.format(True)

    def from_key(self, file: str) -> ...:
        """
        Read the ECC key from a file.

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
            raise TypeError("The file must be a string, not {}".format(type(file)))
        
        # Check if the file exists
        if not os.path.isfile(file):
            raise FileNotFoundError("The file {} does not exist.".format(file))
        
        key = ""

        raise NotImplementedError("This function is not implemented yet.")
    
        with open(file, "rt") as keyfile:
            key = ECC.import_key(keyfile.read())

        # Verify that the key is a private key
        if not key.has_private():
            raise ValueError("The key is not a private key.")
        self._key_pair = key

    def sign(self, data: bytes) -> bytes:
        """Sign the data."""
        if not isinstance(data, bytes):
            raise TypeError("The data must be bytes, not {}".format(type(data)))

        raise NotImplementedError("This function is not implemented yet.")

    @staticmethod
    def signature_valid(data: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Check if the signed data is valid.

        Parameters
        ----------
        data : bytes
            The data to check.
        signature : bytes
            The signature to check.
        public_key : bytes
            The public key to check the signature with.

        Returns
        -------
        bool
            True if the signature is valid, False otherwise.
        """

        raise NotImplementedError("This function is not implemented yet.")
        if not isinstance(data, bytes):
            raise TypeError("The data must be bytes, not {}".format(type(data)))
        if not isinstance(signature, bytes):
            raise TypeError(
                "The signature must be bytes, not {}".format(type(signature))
            )
        if not isinstance(public_key, bytes):
            raise TypeError(
                "The public key must be bytes, not {}".format(type(public_key))
            )

        data_hash = Utils.hash_data(data, finalize=False, type="sha512")
        public_key = ECC.import_key(public_key)
        signature_scheme_obj = eddsa.new(public_key, mode="rfc8032")

        try:
            # Verify the signature
            signature_scheme_obj.verify(data_hash, signature)
            return True
        except ValueError:
            return False
        
    def encrypt(self, message: bytes, receiver_public_key: bytes) -> bytes:
        """
        Encrypt the message.

        For now signing is not yet implemented
        """
        if not isinstance(message, bytes):
            raise TypeError("The message must be bytes, not {}".format(type(message)))
        if not isinstance(receiver_public_key, bytes):
            raise TypeError(
                "The receiver_public_key must be bytes, not {}".format(
                    type(receiver_public_key)
                )
            )

        return encrypt(receiver_public_key, message)

    def decrypt(self, encrypted: bytes) -> ...:
        """Decrypt the message."""
        return decrypt(self._encryption_keypair.to_hex(), encrypted)