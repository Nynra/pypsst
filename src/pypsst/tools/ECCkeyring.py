from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
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
            self._key_pair = self.generate_keypair()

    @property
    def public_key_string(self) -> str:
        """Get the public key string."""
        # Export the public key from the keypare as a utf-8 string
        return self._key_pair.public_key().export_key(format="PEM")

    @property
    def public_key(self) -> bytes:
        """Get the public key."""
        # Export the public key from the keypare as a utf-8 string
        return self._key_pair.public_key().export_key(format="PEM").encode()

    def generate_keypair(self) -> ECC:
        """
        Generate a new RSA keypair.
        
        A new keypair will be generated every time this function is called.
        The keypair will be of curve type ed25519.
        """
        return ECC.generate(curve="ed25519")

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
        with open(file, "rt") as keyfile:
            key = ECC.import_key(keyfile.read())

        # Verify that the key is a private key
        if not key.has_private():
            raise ValueError("The key is not a private key.")
        self._key_pair = key

    def sign(self, data: Union[bytes, dict]) -> bytes:
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
            raise TypeError("The data must be bytes, not {}".format(type(data)))
        if isinstance(data, dict):
            # Convert the dict to bytes
            data = str(data).encode()

        data_hash = Utils.hash_data(data, finalize=False, type="sha512")
        # Create an object that can sign the data with the RSA keypair
        signature_scheme_obj = eddsa.new(self._key_pair, mode="rfc8032")
        signature = signature_scheme_obj.sign(data_hash)
        return signature

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
        
    def encrypt(self, *args, **kwargs) -> ...:
        raise NotImplementedError("ECC cannot be used for encryption unless a key exchange is done.")
    
    def decrypt(self, *args, **kwargs) -> ...:
        raise NotImplementedError("ECC cannot be used for encryption unless a key exchange is done.")