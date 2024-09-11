from typing import Any, Union
from collections.abc import MutableMapping
import rlp
from .utils import Utils
import os
from .exceptions import ContactNotFoundError, ContactExistsError
from .RSAkeyring import RsaKeyring
import json


class KeyAlreadySetError(Exception):
    def __init__(self, message: str) -> ...:
        super().__init__(message)


class KeyNotSetError(Exception):
    def __init__(self, message: str) -> ...:
        super().__init__(message)


class Contact(MutableMapping):
    """
    A class to represent a contact.

    This class is used to represent a contact. A contact is a person or
    entity that you can communicate with using PyPSST. A contact has a
    nickname, a public key (ECC and/or RSA), and a key type. The nickname is a string that
    is used to identify the contact. The public key is a string that is
    used to encrypt messages to the contact. The key type is a string that
    is used to identify the type of the public key. The key type can be
    either ECC or RSA.
    """

    def __init__(
        self,
        nickname: str,
        key_type: str = "rsa",
        authentication_key: Union[str, bytes, None] = None,
        encryption_key: Union[str, bytes, None] = None,
    ) -> ...:
        """
        Initialize a new Contact object.


        Parameters
        ----------
        nickname : str
            The nickname of the contact.

            .. attention::
                The nickname is used to identify the contact. It is not possible
                to change the nickname of a contact after it has been created.

        public_key : str, bytes
            The public key of the contact.
        key_type : str, optional
            The type of the public key of the contact, this can be ECC or RSA.
            The default is RSA.
        authentication_key : str, bytes, optional
            The authentication key of the contact. The default is None.
        encryption_key : str, bytes, optional
            The encryption key of the contact. The default is None.
        """
        if not isinstance(nickname, str):
            raise TypeError("nickname must be a string, not {}".format(type(nickname)))
        if not isinstance(key_type, (str, bytes)):
            raise TypeError(
                "key_type must be a string or bytes, not {}".format(type(key_type))
            )
        if not isinstance(authentication_key, (str, bytes, type(None))):
            raise TypeError(
                "authentication_key must be a string or bytes, not {}".format(
                    type(authentication_key)
                )
            )
        if not isinstance(encryption_key, (str, bytes, type(None))):
            raise TypeError(
                "encryption_key must be a string or bytes, not {}".format(
                    type(encryption_key)
                )
            )
        if key_type.lower() not in ["ecc", "rsa"]:
            raise ValueError("key_type must be ECC or RSA, not {}".format(key_type))
        self._nickname = nickname
        self._primary_key = key_type.lower()
        self._ecc_keys = Contact.KeyStorage(key_type="ecc")
        self._rsa_keys = Contact.KeyStorage(key_type="rsa")

        if authentication_key is not None and key_type.lower() == "ecc":
            self._ecc_keys.set_authentication_key(authentication_key)
        elif authentication_key is not None and key_type.lower() == "rsa":
            self._rsa_keys.set_authentication_key(authentication_key)

        if encryption_key is not None and key_type.lower() == "ecc":
            self._ecc_keys.set_encryption_key(encryption_key)
        elif encryption_key is not None and key_type.lower() == "rsa":
            self._rsa_keys.set_encryption_key(encryption_key)

    def _check_json_serializable(self, value, raise_exception: bool = True) -> bool:
        """
        Check if the given value is json serializable.

        This is a support function for the Contact class. It checks if the given
        value is json serializable. It is not meant to be used directly.
        """
        # Check if the value is json serializable
        serializable = True
        try:
            json.dumps(value)
        except TypeError:
            serializable = False

        # Check if the value has the to_json and from_json methods
        has_to_json = hasattr(value, "to_json")
        has_from_json = hasattr(value, "from_json")

        if not serializable and not (has_to_json and has_from_json):
            if raise_exception:
                raise TypeError(
                    "The value {} is not json serializable and does not have the to_json and from_json methods.".format(
                        value
                    )
                )
            else:
                return False

        return True

    # DUNDER METHODS
    def __hash__(self) -> int:
        """Return the hash of the Contact object."""
        return int(Utils.hash_data(self.encode_rlp()), 16)

    def __eq__(self, other) -> bool:
        """Check if two Contact objects are equal."""
        if not isinstance(other, Contact):
            return False
        return self.__hash__() == other.__hash__()

    # PROPERTIES
    @property
    def nickname(self) -> str:
        """Get the nickname of the contact."""
        return self._nickname

    @property
    def primary_key(self) -> str:
        """Get the primary key of the contact."""
        return self._primary_key

    @property
    def auth_key(self) -> str:
        """Get the authentication key of the contact."""
        if self._primary_key == "ecc":
            return self._ecc_keys.auth_key
        elif self._primary_key == "rsa":
            return self._rsa_keys.auth_key
        else:
            raise ValueError(
                "you should not have been able to get here, not {}".format(
                    self._primary_key
                )
            )

    @property
    def enc_key(self) -> str:
        """Get the encryption key of the contact."""
        if self._primary_key == "ecc":
            return self._ecc_keys.enc_key
        elif self._primary_key == "rsa":
            return self._rsa_keys.enc_key
        else:
            raise ValueError(
                "you should not have been able to get here, not {}".format(
                    self._primary_key
                )
            )

    @property
    def ecc_keys(self) -> "Contact.KeyStorage":
        """Get the ECC keys of the contact."""
        return self._ecc_keys

    @property
    def rsa_keys(self) -> "Contact.KeyStorage":
        """Get the RSA keys of the contact."""
        return self._rsa_keys

    # FUNCTIONS
    def add_key(self, key: Union[str, bytes], key_type: str) -> ...:
        """
        Add a key to the contact.

        Parameters
        ----------
        key : str, bytes
            The key to add to the contact.
        key_type : str
            The type of the key to add to the contact. The key type must followw
            the following format: <key_type>_<key_use>. The key use can be
            auth (authentication) or enc (encryption). For example, if you want
            to add an authentication ECC key, the key_type should be ecc_auth.
        """
        if not isinstance(key, (str, bytes)):
            raise TypeError("key must be a string or bytes, not {}".format(type(key)))
        if not isinstance(key_type, str):
            raise TypeError("key_type must be a string, not {}".format(type(key_type)))

        content = key_type.split("_")
        if len(content) != 2:
            raise ValueError("Invalid key_type.")

        key_type = content[0]
        key_use = content[1]

        if key_type.lower() not in ["ecc", "rsa"]:
            raise ValueError("key_type must be ECC or RSA, not {}".format(key_type))

        if key_use.lower() not in ["auth", "enc"]:
            raise ValueError("key_use must be auth or enc, not {}".format(key_use))

        if key_type.lower() == "ecc":
            if key_use.lower() == "auth":
                self._ecc_keys.set_authentication_key(key)
            elif key_use.lower() == "enc":
                self._ecc_keys.set_encryption_key(key)
            else:
                raise ValueError("you should not have been able to get here")

        elif key_type.lower() == "rsa":
            if key_use.lower() == "auth":
                self._rsa_keys.set_authentication_key(key)
            elif key_use.lower() == "enc":
                self._rsa_keys.set_encryption_key(key)
            else:
                raise ValueError("you should not have been able to get here")

        else:
            raise ValueError("you should not have been able to get here")

    def remove_key(self, key_type: str) -> ...:
        """
        Remove a key from the contact.

        Parameters
        ----------
        key_type : str
            The type of the key to remove from the contact. The key type must followw
            the following format: <key_type>_<key_use>. The key use can be
            auth (authentication) or enc (encryption). For example, if you want
            to remove an authentication ECC key, the key_type should be ecc_auth.
        """
        if not isinstance(key_type, str):
            raise TypeError("key_type must be a string, not {}".format(type(key_type)))

        content = key_type.split("_")
        if len(content) != 2:
            raise ValueError("Invalid key_type.")

        key_type = content[0]
        key_use = content[1]

        if key_type.lower() not in ["ecc", "rsa"]:
            raise ValueError("key_type must be ECC or RSA, not {}".format(key_type))

        if key_use.lower() not in ["auth", "enc"]:
            raise ValueError("key_use must be auth or enc, not {}".format(key_use))

        if key_type.lower() == "ecc":
            if key_use.lower() == "auth":
                self._ecc_keys.set_authentication_key(None)
            elif key_use.lower() == "enc":
                self._ecc_keys.set_encryption_key(None)
            else:
                raise ValueError("you should not have been able to get here")

        elif key_type.lower() == "rsa":
            if key_use.lower() == "auth":
                self._rsa_keys.set_authentication_key(None)
            elif key_use.lower() == "enc":
                self._rsa_keys.set_encryption_key(None)
            else:
                raise ValueError("you should not have been able to get here")

        else:
            raise ValueError("you should not have been able to get here")

    # CODEC
    def encode_json(self) -> str:
        """
        Encode the Contact object as a JSON string.

        Returns
        -------
        str
            The Contact object encoded as a JSON string.
        """
        data = {
            "nickname": self._nickname,
            "primary_key": self._primary_key,
            "ecc_keys": self._ecc_keys.encode_json(),
            "rsa_keys": self._rsa_keys.encode_json(),
        }

        return json.dumps({k: data[k] for k in sorted(data.keys())})

    def to_json(self) -> str:
        """Encode the Contact object as a JSON string, alias for encode_json."""
        return self.encode_json()

    @staticmethod
    def decode_json(data: str) -> "Contact":
        """
        Decode a JSON string into a Contact object.

        Parameters
        ----------
        data : str
            The JSON string to decode.

        Returns
        -------
        Contact
            The decoded Contact object.
        """
        data = json.loads(data)

        contact = Contact(nickname=data["nickname"], key_type=data["primary_key"])
        contact.ecc_keys = Contact.KeyStorage.decode_json(data["ecc_keys"])
        contact.rsa_keys = Contact.KeyStorage.decode_json(data["rsa_keys"])
        return contact

    @classmethod
    def from_json(cls, data: str) -> "Contact":
        """Decode a JSON string into a Contact object, alias for decode_json."""
        return cls.decode_json(data)
    
    class KeyStorage:
        def __init__(
            self,
            key_type: str,
            authentication_key: Union[str, bytes, None] = None,
            encryption_key: Union[str, bytes, None] = None,
        ) -> ...:
            """
            Initialize a new KeyStorage object.

            .. note::
                For consistency everything inside the class in handles as strings
                for byte objects this means they are hex encoded.

            Parameters
            ----------
            key_type : str
                The type of the key to store. Can be ECC or RSA.
            authentication_key : str, bytes, optional
                The authentication key to store. The default is None.
            encryption_key : str, bytes, optional
                The encryption key to store. The default is None.
            """
            # Check the typing
            if not isinstance(key_type, str):
                raise TypeError("key_type must be a string, not {}".format(type(key_type)))
            if key_type.lower() not in ["ecc", "rsa"]:
                raise ValueError("key_type must be ECC or RSA, not {}".format(key_type))
            if not isinstance(authentication_key, (str, bytes, type(None))):
                raise TypeError(
                    "authentication_key must be a string or bytes, not {}".format(
                        type(authentication_key)
                    )
                )
            if not isinstance(encryption_key, (str, bytes, type(None))):
                raise TypeError(
                    "encryption_key must be a string or bytes, not {}".format(
                        type(encryption_key)
                    )
                )
            
            self._key_type = key_type

            # Convert to the right type
            if authentication_key is not None:
                if isinstance(authentication_key, bytes):
                    authentication_key = authentication_key.hex()
                self._check_key_valid(authentication_key)

            if encryption_key is not None:
                if isinstance(encryption_key, bytes):
                    encryption_key = encryption_key.hex()
                self._check_key_valid(encryption_key)

            self._authentication_key = authentication_key
            self._encryption_key = encryption_key

        # PROPERTIES
        @property
        def key_type(self) -> str:
            """Get the type of the key."""
            return self._key_type

        @property
        def authentication_key(self) -> str:
            """Get the authentication key."""
            return self._authentication_key

        @property
        def auth_key(self) -> str:
            """Get the authentication key, alias for authentication_key."""
            return self.authentication_key

        @property
        def encryption_key(self) -> str:
            """Get the encryption key."""
            return self._encryption_key

        @property
        def enc_key(self) -> str:
            """Get the encryption key, alias for encryption_key."""
            return self.encryption_key

        # FUNCTIONS
        def _check_key_valid(self, key: str) -> bool:
            """Check if the given key is valid.

            This is a support function for the KeyStorage class. It checks if the given
            key is valid. It is not meant to be used directly.
            """
            if not isinstance(key, str):
                raise TypeError("key must be a string, not {}".format(type(key)))
            key = bytes.fromhex(key)

            if self._key_type == "ecc":
                raise NotImplementedError("This function is not implemented yet.")
                return Utils.ecc_key_valid(key)
            elif self._key_type == "rsa":
                return Utils.rsa_key_valid(key)
            else:
                raise ValueError(
                    "Invalid key type, must be ECC or RSA, not {}".format(type)
                )

        def set_authentication_key(self, key: Union[str, bytes, None]) -> ...:
            """
            Set the authentication key.

            Parameters
            ----------
            key : str, bytes, None
                The authentication key to set. If set to None, the authentication key will be
                removed.
            """
            if not isinstance(key, (str, bytes, None)):
                raise TypeError(
                    "key must be a string, bytes or None, not {}".format(type(key))
                )

            if key is None:
                # Just remove the key and return
                self._authentication_key = None
                return

            # Check if the key is already set
            if self._authentication_key is not None:
                raise KeyAlreadySetError("The authentication key is already set.")

            # Check if the key is valid
            self._check_key_valid(key)
            self._authentication_key = key

        def set_encryption_key(self, key: Union[str, bytes, None]) -> ...:
            """
            Set the encryption key.

            Parameters
            ----------
            key : str, bytes, None
                The encryption key to set. If set to None, the encryption key will be
                removed.
            """
            if not isinstance(key, (str, bytes, None)):
                raise TypeError(
                    "key must be a string, bytes or None, not {}".format(type(key))
                )

            if key is None:
                # Just remove the key and return
                self._encryption_key = None
                return

            # Check if the key is already set
            if self._encryption_key is not None:
                raise KeyAlreadySetError("The encryption key is already set.")

            # Check if the key is valid
            self._check_key_valid(key)
            self._encryption_key = key

        def get_authentication_key(self) -> Union[str, bytes]:
            """
            Get the authentication key.

            Returns
            -------
            str, bytes
                The authentication key.
            """
            # Check if the key is set
            if self._authentication_key is None:
                raise KeyNotSetError("The authentication key is not set.")
            return self._authentication_key

        def get_encryption_key(self) -> Union[str, bytes]:
            """
            Get the encryption key.

            Returns
            -------
            str, bytes
                The encryption key.
            """
            # Check if the key is set
            if self._encryption_key is None:
                raise KeyNotSetError("The encryption key is not set.")
            return self._encryption_key

        # CODEC
        def encode_json(self) -> str:
            """Encode the KeyStorage object as a JSON string."""
            data = {
                "key_type": self._key_type,
                "authentication_key": self._authentication_key,
                "encryption_key": self._encryption_key,
            }
            return json.dumps(data)

        @staticmethod
        def decode_json(data: str) -> "Contact.KeyStorage":
            """Decode a JSON string into a KeyStorage object."""
            data = json.loads(data)
            key_type = data.pop("key_type")
            authentication_key = data.pop("authentication_key")
            encryption_key = data.pop("encryption_key")
            return Contact.KeyStorage(
                key_type=key_type,
                authentication_key=authentication_key,
                encryption_key=encryption_key,
            )


class ContactBook(MutableMapping):
    """
    The ContactBook class is used to represent a contactbook.

    The contactbook is not much more than a dict that with Contact objects that
    can be encrypted and saved to media. The class can be used as a dict
    containing contacts or using the provided functions.

    .. warning::
        The ContactBook class is not thread safe.
    """

    def __init__(
        self,
        filename: str,
        create_new: bool = False,
        unlock_method: str = "password",
        password: Union[str, None] = None,
        key_file: Union[str, None] = None,
        key_type: str = "RSA",
        contact_storage={},
        verbose: bool = False,
    ) -> ...:
        """
        Initialize a new ContactBook object.

        .. note::
            The contact_storage accepts any class that inherits from MutableMapping
            and implements the __getitem__, __setitem__, __delitem__, __iter__,
            __len__, and __contains__ methods.

        Parameters
        ----------
        filename : str, optional
            The file that is used for the contactbook. If the file does not
            exist, it will be created. The default is None.
        create_new : bool, optional
            If True, a new contactbook will be created. If False, the contactbook
            will be loaded from the given file. The default is False.
        unlock_method : str, optional
            The method to use to unlock the contactbook. Can be password or
            keyfile. The default is password.
        password : str, optional
            The password to use to encrypt the contactbook. The default is None.
        key_file : str, optional
            The file that contains the key to use to encrypt the contactbook.
            The default is None.
        key_type : str, optional
            The type of the key to use to encrypt the contactbook. Can be ECC
            or RSA. The default is RSA.
        contact_storage : dict, optional
            A dict containing the contacts to add to the contactbook. The default
            is {}. Any class inheriting from MutableMapping and implementing the
            __getitem__, __setitem__, etc. methods can be used as contact_storage.
        verbose : bool, optional
            If True, the ContactBook will print debug messages. The default is False.
        """
        # Check if the arguments are of the correct type
        if not isinstance(filename, str):
            raise TypeError("filename must be a string, not {}".format(type(filename)))
        if not isinstance(create_new, bool):
            raise TypeError(
                "create_new must be a bool, not {}".format(type(create_new))
            )
        if not isinstance(unlock_method, str):
            raise TypeError(
                "unlock_method must be a string, not {}".format(type(unlock_method))
            )
        if not isinstance(password, (str, type(None))):
            raise TypeError(
                "password must be a string or None, not {}".format(type(password))
            )
        if not isinstance(key_file, (str, type(None))):
            raise TypeError(
                "key_file must be a string or None, not {}".format(type(key_file))
            )

        # Check if the given contact storage is valid
        if not isinstance(contact_storage, MutableMapping):
            raise TypeError(
                "contact_storage must be a MutableMapping, not {}".format(
                    type(contact_storage)
                )
            )

        # Check if we have the right data for unlocking an existing file
        if key_file is not None and password is not None:
            raise ValueError("password and key_file cannot both be set.")
        elif key_file is None and password is None:
            raise ValueError("password or key_file must be set.")

        if unlock_method.lower() not in ["password", "keyfile"]:
            raise ValueError(
                "unlock_method must be password or keyfile, not {}".format(
                    unlock_method
                )
            )
        elif unlock_method == "password" and password is None:
            raise ValueError("password must be set when unlock_method is password.")
        else:
            if unlock_method.lower() == "keyfile" and key_file is None:
                raise ValueError("key_file must be set when unlock_method is keyfile.")
            if unlock_method.lower() == "keyfile" and key_type.lower() in [
                "ecc",
                "rsa",
            ]:
                raise ValueError(
                    "key_type must be either ECC or RSA when unlock_method is keyfile."
                )

        self._contacts = contact_storage
        self._unlock_method = unlock_method
        self._password = password
        self._key_file = key_file
        self._filename = filename
        self._key_type = key_type
        self._verbose = verbose

        if unlock_method.lower() == "password":
            if not create_new:
                self.load_contacts(password, filename, unlock_method)
            else:
                self.save_contacts(password, filename, unlock_method)
        elif unlock_method.lower() == "keyfile":
            if not create_new:
                self.load_contacts(key_file, filename, unlock_method)
            else:
                self.save_contacts(key_file, filename, unlock_method)

    # DUNDER METHODS
    def __getitem__(self, key: str) -> Contact:
        """Return the Contact with the given nickname."""
        self.get_contact(key)

    def __setitem__(self, key: str, value: Contact) -> ...:
        """Set the Contact with the given nickname.
        
        It is not possible to overwrite an existing contact with this method.
        """
        if not isinstance(key, str):
            raise TypeError("key must be a string, not {}".format(type(key)))

        if key.lower() in self._contacts.keys():
            raise ContactExistsError(
                "Contact with nickname {} already exists.".format(key)
            )
        self.update_contact(value)
        

    def __delitem__(self, key: str) -> ...:
        """Delete the Contact with the given nickname."""
        self.delete_contact(key)

    def __iter__(self):
        """Get an iterator for the contacts in the ContactBook object."""
        return iter(self._contacts.values())

    def __len__(self) -> int:
        """Get the number of contacts in the ContactBook object."""
        return len(self._contacts.keys())

    def __contains__(self, key: str) -> bool:
        """Wrapper for the contains function"""
        return self.contains(key)

    # CONTACT MANAGING FUNCTIONS
    def load_contacts(
        self, key: str, key_type: str, filename: str, contact_storage: MutableMapping
    ) -> ...:
        """
        Load the contacts from the contactbook file.

        Parameters
        ----------
        key : str
            The key to use to decrypt the contactbook.
        key_type : str
            The type of the key to use to decrypt the contactbook. Can be ECC,
            RSA, or password.
        filename : str
            The file that is used for the contactbook. If no path is given, the
            current working directory will be used.
        contact_storage : MutableMapping
            The contact storage to use for the contacts.
        """
        if not isinstance(key, str):
            raise TypeError("key must be a string, not {}".format(type(key)))
        if not isinstance(filename, (str, type(None))):
            raise TypeError(
                "filename must be a string or None, not {}".format(type(filename))
            )
        if not isinstance(key_type, str):
            raise TypeError("key_type must be a string, not {}".format(type(key_type)))
        if key_type.lower() not in ["password", "ecc", "rsa"]:
            raise ValueError(
                "key_type must be password or key_file, not {}".format(key_type)
            )
        if not isinstance(contact_storage, (MutableMapping, dict)):
            raise TypeError(
                "contact_storage must be a MutableMapping, not {}".format(
                    type(contact_storage)
                )
            )

        # Check if the contactbook file exists
        if not Utils.file_exists(filename):
            raise ValueError("File {} does not exist.".format(filename))

        # If the unlock method is key_file, check if the key file exists
        if key_type.lower() in ["ecc", "rsa"]:
            if not Utils.file_exists(key):
                raise ValueError("File {} does not exist.".format(key))

        with open(filename, "rb") as f:
            data = f.read()

        # Unlock the contactbook
        if key_type.lower() == ["rsa", "ecc"]:
            with open(key, "rb") as f:
                if key_type.lower() == "ecc":
                    raise NotImplementedError("ECC keyring not implemented yet.")
                    keyring = EccKeyring(f.read())
                elif key_type.lower() == "rsa":
                    keyring = RsaKeyring(f.read())

            data = keyring.decrypt(data)

        elif key_type == "password":
            data = Utils.decrypt(data, key)
        else:
            raise ValueError(
                "you should not have been able to get here, not {}".format(key_type)
            )

        data = rlp.decode(data)

        # Check if the metadata is correct
        metadata = data.pop()
        metadata = {k: v for k, v in metadata}
        if key_type.lower() == "password":
            if metadata["password_hash"] != Utils.hash_data(key.encode()):
                raise ValueError("Incorrect password.")
        elif key_type.lower() in ["ecc", "rsa"]:
            if metadata["public_key"] != keyring.public_key:
                raise ValueError("Incorrect key.")
        else:
            raise ValueError("unknown key_type {}".format(key_type))

        self._contacts = contact_storage
        for k, v in data:
            self._contacts[k.decode()] = Contact.decode_rlp(v)

    def save_contacts(self, key: str, key_type: str, filename: str) -> ...:
        """
        Save the contacts to the contactbook file.

        Parameters
        ----------
        key : str
            The key to use to encrypt the contactbook.
        key_type : str
            The type of the key to use to encrypt the contactbook. Can be ECC,
            RSA, or password. If the key_type is password, the key will be used
            to encrypt the contactbook. If the key_type is ECC or RSA, the key
            will be used to encrypt the contactbook file, and the public key
            will be stored in the contactbook file.

            .. warning::
                Remember which method you used to encrypt the contactbook, as
                you will need it to decrypt the contactbook. It will not be
                stored in the contactbook file.

        filename : str
            The file that is used for the contactbook. If the file does not
            exist, it will be created. If no path is given, the file will be
            created in the current working directory.

            .. warning::
                If the file already exists, it will be overwritten.
        """
        if not isinstance(key, str):
            raise TypeError("key must be a string, not {}".format(type(key)))
        if not isinstance(filename, str):
            raise TypeError("filename must be a string, not {}".format(type(filename)))
        if not isinstance(key_type, str):
            raise TypeError("key_type must be a string, not {}".format(type(key_type)))
        if key_type.lower() not in ["password", "ecc", "rsa"]:
            raise ValueError(
                "key_type must be password or key_file, not {}".format(key_type)
            )

        # Check if the folder exists
        if (
            not Utils.dir_exists(os.path.dirname(filename))
            and os.path.dirname(filename) != ""
        ):
            raise ValueError(
                "Folder {} does not exist.".format(os.path.dirname(filename))
            )

        # Check if the key file exists
        if key_type.lower() in ["ecc", "rsa"]:
            if not Utils.file_exists(key):
                raise ValueError("File {} does not exist.".format(key))

        # Encode the data
        encoded = [[k.encode(), v.encode_rlp()] for k, v in self._contacts.items()]
        metadata = [[b"key_type", key_type.encode()]]
        data = rlp.encode(encoded)

        # Encrypt the data
        if key_type.lower() == "ecc":
            raise NotImplementedError("ECC keyring not implemented yet.")
            with open(key, "rb") as f:
                keyring = EccKeyring(f.read())

            # Append the public key to the metadata
            metadata.append([b"public_key", keyring.public_key])
            data.append(rlp.encode(metadata))
            data = keyring.encrypt(data)
        elif key_type.lower() == "rsa":
            with open(key, "rb") as f:
                keyring = RsaKeyring(f.read())

            # Append the public key to the metadata
            metadata.append([b"public_key", keyring.public_key])
            data.append(rlp.encode(metadata))
            data = keyring.encrypt(data)
        elif key_type.lower() == "password":
            # Add a hash of the password to the metadata
            metadata.append([b"password_hash", Utils.hash_data(key.encode())])
            data.append(rlp.encode(metadata))
            data = Utils.encrypt(self._encode_rlp(), key)

        # Write the data to the file
        with open(filename, "wb") as f:
            f.write(data)

    # FUNCTIONS
    def add_contact(self, contact: Contact) -> ...:
        """
        Add a contact to the contactbook.

        Parameters
        ----------
        contact : Contact
            The contact to add to the contactbook.
        """
        if not isinstance(contact, Contact):
            raise TypeError("contact must be a Contact, not {}".format(type(contact)))
        
        # Check if the nickname is available
        if contact.nickname in self._contacts:
            raise ContactExistsError(
                "Contact with nickname {} already exists.".format(contact.nickname)
            )
        
        # Check if the public key is valid
        if contact.key_type.lower() == "rsa":
            if not Utils.rsa_key_valid(contact.public_key):
                raise ValueError("Invalid RSA public key.")
        elif contact.key_type.lower() == "ecc":
            if not Utils.ecc_key_valid(contact.public_key):
                raise ValueError("Invalid ECC public key.")
        
        self._contacts[contact.nickname.lower()] = contact

    def update_contact(self, contact: Contact) -> ...:
        """
        Update a contact in the contactbook.

        Parameters
        ----------
        contact : Contact
            The contact to update in the contactbook.
        """
        # Check if the nickname is in the contactbook
        if contact.nickname.lower() not in self._contacts:
            raise ContactNotFoundError(
                "Contact with nickname {} not found.".format(contact.nickname)
            )
        
        self._contacts[contact.nickname.lower()] = contact

    def delete_contact(self, nickname: str) -> ...:
        """Wrapper for the remove_contact method."""
        self.remove_contact(nickname)

    def remove_contact(self, nickname: str) -> ...:
        """
        Remove a contact from the contactbook.

        Parameters
        ----------
        nickname : str
            The nickname of the contact to remove from the contactbook.
        """
        if not isinstance(nickname, str):
            raise TypeError("nickname must be a string, not {}".format(type(nickname)))

        # Check if the nickname is in the contactbook
        if nickname.lower() not in self._contacts:
            raise ContactNotFoundError(
                "Contact with nickname {} not found.".format(nickname)
            )

        del self._contacts[nickname.lower()]

    def get_contact(self, nickname: str) -> Contact:
        """
        Get a contact from the contactbook.

        Parameters
        ----------
        nickname : str
            The nickname of the contact to get from the contactbook.

        Returns
        -------
        Contact
            The contact with the given nickname.
        """
        if not isinstance(nickname, str):
            raise TypeError("nickname must be a string, not {}".format(type(nickname)))

        # Check if the nickname is in the contactbook
        if nickname.lower() not in self._contacts:
            raise ContactNotFoundError(
                "Contact with nickname {} not found.".format(nickname)
            )

        return self._contacts[nickname.lower()]

    def contains(self, nickname: str) -> bool:
        """
        Check if the contactbook contains a contact with the given nickname.

        Parameters
        ----------
        nickname : str
            The nickname of the contact to check for.

        Returns
        -------
        bool
            True if the contactbook contains a contact with the given nickname,
            False otherwise.
        """
        if not isinstance(nickname, str):
            raise TypeError("nickname must be a string, not {}".format(type(nickname)))

        return nickname.lower() in self._contacts

    # CODEC
    def encode_json(self) -> str:
        """
        Encode the ContactBook object as a JSON string.

        Returns
        -------
        str
            The ContactBook object encoded as a JSON string.
        """
        data = {}
        for k, v in self._contacts.items():
            data[k] = v.encode_json()
        return json.dumps({k: data[k] for k in sorted(data.keys())})
    
    def to_json(self) -> str:
        """
        Encode the ContactBook object as a JSON string, alias for encode_json.

        Returns
        -------
        str
            The ContactBook object encoded as a JSON string.
        """
        return self.encode_json()
    
    @staticmethod
    def decode_json(data: str) -> "ContactBook":
        """
        Decode a JSON string into a ContactBook object.

        Parameters
        ----------
        data : str
            The JSON string to decode.

        Returns
        -------
        ContactBook
            The decoded ContactBook object.
        """
        data = json.loads(data)
        for k, v in data.items():
            data[k] = Contact.decode_json(v)
        return ContactBook(contact_storage=data)
    
    @classmethod
    def from_json(cls, data: str) -> "ContactBook":
        """
        Decode a JSON string into a ContactBook object, alias for decode_json.

        Parameters
        ----------
        data : str
            The JSON string to decode.

        Returns
        -------
        ContactBook
            The decoded ContactBook object.
        """
        return cls.decode_json(data)
