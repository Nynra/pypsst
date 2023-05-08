# -*- coding: utf-8 -*-
from Crypto.Hash import SHA256, SHA512
from Crypto.Cipher import AES
from typing import Union
import time
import uuid
import os


class Utils:
    """Some utilities that are used in multiple classes."""

    @staticmethod
    def get_timestamp() -> bytes:
        """Returns the current timestamp."""
        return str(time.time()).encode()

    @staticmethod
    def get_id() -> bytes:
        """
        Returns a random id.

        Uses uuid4 to generate a random id.
        """
        return uuid.uuid4().hex.encode()

    @classmethod
    def hash_data(
        cls, data: bytes, finalize=True, type="sha256"
    ) -> Union[bytes, SHA256.SHA256Hash, SHA512.SHA512Hash]:
        """
        Hash the given data.

        Parameters
        ----------
        data : bytes
            The data to hash.
        finalize : bool, optional
            If True, the hash will be finalized and the hexdigest will be
            returned. If False, the hash object will be returned. The default
            is True.
        type : str, optional
            The type of hash to use. Can be sha256 or sha512. The default is
            sha256.

        Returns
        -------
        bytes or SHA256Hash or SHA512Hash
            The hash of the data.
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes.")
        if type == "sha256":
            return cls.sha256(data, finalize)
        elif type == "sha512":
            return cls.sha512(data, finalize)
        else:
            raise ValueError(
                "Invalid hash type {}, should be sha256 or sha512.".format(type)
            )

    @staticmethod
    def sha256(data: bytes, finalize: bool = True) -> Union[bytes, SHA256.SHA256Hash]:
        """
        Hash the given data with SHA256.

        Parameters
        ----------
        data : bytes
            The data to hash.
        finalize : bool, optional
            If True, the hash will be finalized and the hexdigest will be
            returned. If False, the hash object will be returned. The default
            is True.

        Returns
        -------
        bytes or SHA256Hash
            The hash of the data.
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes.")
        if finalize:
            hash_data = SHA256.new(data=data)
            return hash_data.hexdigest().encode()
        else:
            return SHA256.new(data=data)

    @staticmethod
    def sha512(data: bytes, finalize: bool = True) -> Union[bytes, SHA512.SHA512Hash]:
        """
        Hash the given data with SHA512.

        Parameters
        ----------
        data : bytes
            The data to hash.
        finalize : bool, optional
            If True, the hash will be finalized and the hexdigest will be
            returned. If False, the hash object will be returned. The default
            is True.

        Returns
        -------
        bytes or SHA512Hash
            The hash of the data.
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes.")
        if finalize:
            hash_data = SHA512.new(data=data)
            return hash_data.hexdigest().encode()
        else:
            return SHA512.new(data=data)

    @staticmethod
    def file_exists(filename: str) -> bool:
        """
        Check if a file exists.

        If the filename has ./ in front of it, the current working directory
        will be prepended to the filename. Otherwise it is assumed that the
        filename is an absolute path.

        Parameters
        ----------
        filename : str
            The filename to check.

        Returns
        -------
        bool
            True if the file exists, False otherwise.
        """
        if not isinstance(filename, str):
            raise TypeError("Filename must be a string.")
        if filename.startswith("./"):
            filename = os.path.join(os.getcwd(), filename[2:])
        return os.path.isfile(filename)
    
    @staticmethod
    def dir_exists(dirname: str) -> bool:
        """
        Check if a directory exists.

        If the dirname has ./ in front of it, the current working directory
        will be prepended to the dirname. Otherwise it is assumed that the
        dirname is an absolute path.

        Parameters
        ----------
        dirname : str
            The dirname to check.

        Returns
        -------
        bool
            True if the directory exists, False otherwise.
        """
        if not isinstance(dirname, str):
            raise TypeError("Dirname must be a string.")
        if dirname.startswith("./"):
            dirname = os.path.join(os.getcwd(), dirname[2:])
        return os.path.isdir(dirname)

    @staticmethod
    def encrypt(data: bytes, password: str) -> bytes:
        """
        Encrypt the given data with the given password.

        The data is encrypted using

        Parameters
        ----------
        data : bytes
            The data to encrypt.
        password : str
            The password to use to encrypt the data.

        Returns
        -------
        bytes
            The encrypted data.
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes.")
        if not isinstance(password, str):
            raise TypeError("Password must be a string.")

        # Encrypt the data using AES
        password = Utils.hash_data(password.encode(), finalize=False).digest()
        cipher = AES.new(password, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # Create a binary blob containing the nonce, tag and ciphertext
        return b"".join([cipher.nonce, tag, ciphertext])

    @staticmethod
    def decrypt(data: bytes, password: str) -> bytes:
        """
        Decrypt the given data with the given password.

        The data is decrypted using

        Parameters
        ----------
        data : bytes
            The data to decrypt.
        password : str
            The password to use to decrypt the data.

        Returns
        -------
        bytes
            The decrypted data.
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes.")
        if not isinstance(password, str):
            raise TypeError("Password must be a string.")

        # Split the data into the nonce, tag and ciphertext
        nonce = data[:16]
        tag = data[16:32]
        ciphertext = data[32:]

        # Decrypt the data using AES
        password = Utils.hash_data(password.encode(), finalize=False).digest()
        cipher = AES.new(password, AES.MODE_EAX, nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
