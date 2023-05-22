from typing import Union
from collections.abc import MutableMapping
import rlp
from .utils import Utils
import os
from .exceptions import ContactNotFoundError, ContactExistsError
from .RSAkeyring import RsaKeyring


class Contact(MutableMapping):
    """
    A class to represent a contact.

    This class is used to represent a contact. A contact is a person or
    entity that you can communicate with using PyPSST. A contact has a
    nickname, a public key, and a key type. The nickname is a string that
    is used to identify the contact. The public key is a string that is
    used to encrypt messages to the contact. The key type is a string that
    is used to identify the type of the public key. The key type can be
    either ECC or RSA.
    """

    def __init__(
        self,
        nickname: str,
        public_key: Union[str, bytes],
        key_type: Union[str, bytes],
        **kwargs
    ) -> ...:
        """
        Initialize a new Contact object.


        Parameters
        ----------
        nickname : str
            The nickname of the contact.
        public_key : str, bytes
            The public key of the contact.
        key_type : str, bytes
            The type of the public key of the contact, this can be ECC or RSA.
        **kwargs : dict
            Any additional keyword arguments to be added to the Contact object.
            Each key and value should be sting types.
        """
        if not isinstance(nickname, str):
            raise TypeError("nickname must be a string, not {}".format(type(nickname)))
        if not isinstance(public_key, (str, bytes)):
            raise TypeError(
                "public_key must be a string or bytes, not {}".format(type(public_key))
            )
        if not isinstance(key_type, (str, bytes)):
            raise TypeError(
                "key_type must be a string or bytes, not {}".format(type(key_type))
            )

        # Try to remove the nickname, public key and key type from the kwargs
        try:
            del kwargs["nickname"]
        except KeyError:
            pass

        for key, value in kwargs.items():
            if not isinstance(key, str):
                raise TypeError(
                    "keyword argument key must be a string, not {}".format(type(key))
                )
            if not isinstance(value, str):
                raise TypeError(
                    "keyword argument value must be a string, not {}".format(
                        type(value)
                    )
                )

        self.nickname = nickname
        self.public_key = public_key if type(public_key) == str else public_key.decode()
        self.key_type = key_type if type(key_type) == str else key_type.decode()
        self.__dict__.update(kwargs)

    # DUNDER METHODS
    def __hash__(self) -> int:
        """Return the hash of the Contact object."""
        return int(Utils.hash_data(self.encode_rlp()), 16)
    
    def __eq__(self, other) -> bool:
        """Check if two Contact objects are equal."""
        if not isinstance(other, Contact):
            return False
        return self.__hash__() == other.__hash__()
    
    def __getitem__(self, key: str) -> str:
        """Return the value of the given key."""
        if not isinstance(key, str):
            raise TypeError("key must be a string, not {}".format(type(key)))
        return self.__dict__[key]
    
    def __setitem__(self, key, value) -> ...:
        """Set the value of the given key."""
        if not isinstance(key, str):
            raise TypeError("key must be a string, not {}".format(type(key)))
        if not isinstance(value, str):
            raise TypeError("value mist be a string, not {}".format(type(value)))
            
        if key.lower() == 'nickname':
            raise ValueError('Cannot change the nickname, as this is used as the key for the contact')
        
        self.__dict__.update({key : value})

    def __delitem__(self, key) -> ...:
        """Delete the given key."""
        if not isinstance(key, str):
            raise TypeError("key must be a string, not {}".format(type(key)))
        
        if key.lower() == 'nickname':
            raise ValueError('Cannot delete the nickname, as this is used as the key for the contact')
        
        del self.__dict__[key]

    def __iter__(self):
        """Return an iterator for the Contact object."""
        return iter(self.__dict__)
    
    def __len__(self) -> int:
        """Return the number of keys in the Contact object."""
        return len(self.__dict__.keys())
    
    def __contains__(self, key) -> bool:
        """Check if the given key is in the Contact object."""
        if not isinstance(key, str):
            raise TypeError("key must be a string, not {}".format(type(key)))
        return key in self.__dict__.keys()
    
    def list_attributes(self) -> list:
        """
        Return a list of all the attributes of the Contact object.

        Returns
        -------
        list
            A list of all the attributes of the Contact object.
        """
        dict = self.__dict__
        del dict["nickname"]
        return list(dict.keys())

    # CODEC
    def encode_rlp(self) -> bytes:
        """
        Encode the Contact object as an RLP byte string.

        Returns
        -------
        bytes
            The Contact object encoded as an RLP string.
        """
        res = [[k.encode(), v.encode()] for k, v in self.__dict__.items()]
        return rlp.encode(res)

    @staticmethod
    def decode_rlp(data: bytes) -> "Contact":
        """
        Decode an RLP byte string into a Contact object.

        Parameters
        ----------
        data : bytes
            The RLP byte string to decode.

        Returns
        -------
        Contact
            The decoded Contact object.
        """
        sedes = rlp.sedes.CountableList(rlp.sedes.List([rlp.sedes.binary] * 2))
        kwargs = rlp.decode(data, sedes)
        kwargs = {k.decode(): v.decode() for k, v in kwargs}
        nickname = kwargs.pop("nickname")
        public_key = kwargs.pop("public_key")
        key_type = kwargs.pop("key_type")
        return Contact(nickname=nickname, 
                       public_key=public_key, 
                       key_type=key_type,
                       **kwargs)


class ContactBook(MutableMapping):
    """
    The ContactBook class is used to represent a contactbook.

    The contactbook is not much more than a dict that with Contact objects that
    can be encrypted and saved to media. The class can be used as a dict 
    containing contacts or using the provided functions.

    .. warning::
        The ContactBook class is not thread safe.
    """


    def __init__(self, filename : str,
                 create_new : bool=False,
                 unlock_method : str='password',
                 password : Union[str, None]=None,
                 key_file : Union[str, None]=None,
                 contact_storage={}) -> ...:
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
        contact_storage : dict, optional
            A dict containing the contacts to add to the contactbook. The default
            is {}. Any class inheriting from MutableMapping and implementing the 
            __getitem__, __setitem__, etc. methods can be used as contact_storage.
        """
        if not isinstance(filename, str):
            raise TypeError("filename must be a string, not {}".format(type(filename)))
        if not isinstance(create_new, bool):
            raise TypeError("create_new must be a bool, not {}".format(type(create_new)))
        if not isinstance(unlock_method, str):
            raise TypeError("unlock_method must be a string, not {}".format(type(unlock_method)))
        if not isinstance(password, (str, type(None))):
            raise TypeError("password must be a string or None, not {}".format(type(password)))
        if not isinstance(key_file, (str, type(None))):
            raise TypeError("key_file must be a string or None, not {}".format(type(key_file)))
        
        if key_file is not None and password is not None:
            raise ValueError("password and key_file cannot both be set.")
        elif key_file is None and password is None:
            raise ValueError("password or key_file must be set.")
        
        if unlock_method == 'password' and password is None:
            raise ValueError("password must be set when unlock_method is password.")
        elif unlock_method == 'keyfile' and key_file is None:
            raise ValueError("key_file must be set when unlock_method is keyfile.")
        
        self._contacts = contact_storage
        self._unlock_method = unlock_method
        self._password = password
        self._key_file = key_file
        self._filename = filename

        if unlock_method == 'password':
            if not create_new:
                self.load_contacts(password, filename, unlock_method)
            else:
                self.save_contacts(password, filename, unlock_method)
        elif unlock_method == 'keyfile':
            if not create_new:
                self.load_contacts(key_file, filename, unlock_method)
            else:
                self.save_contacts(key_file, filename, unlock_method)

    # DUNDER METHODS
    def __hash__(self) -> int:
        """Return the hash of the ContactBook object."""
        return int(Utils.hash_data(self._encode_rlp()).decode(), 16)
    
    def __eq__(self, other) -> bool:
        """Check if two ContactBook objects are equal."""
        if not isinstance(other, ContactBook):
            return False
        
        return self.__hash__() == other.__hash__()
    
    def __getitem__(self, key: str) -> Contact:
        """Return the Contact with the given nickname."""
        if not isinstance(key, str):
            raise TypeError("key must be a string, not {}".format(type(key)))
        return self._contacts[key]
    
    def __setitem__(self, key : str, value : Contact) -> ...:
        """Set the Contact with the given nickname."""
        if not isinstance(key, str):
            raise TypeError("key must be a string, not {}".format(type(key)))
        if not isinstance(value, Contact):
            raise TypeError("value must be a Contact object, not {}".format(type(value)))
        self._contacts[key] = value

    def __delitem__(self, key : str) -> ...:
        """Delete the Contact with the given nickname."""
        if not isinstance(key, str):
            raise TypeError("key must be a string, not {}".format(type(key)))
        del self._contacts[key]

    def __iter__(self):
        """Get an iterator for the contacts in the ContactBook object."""
        return iter(self._contacts.values())
    
    def __len__(self) -> int:
        """Get the number of contacts in the ContactBook object."""
        return len(self._contacts.keys())
    
    def __contains__(self, key : str) -> bool:
        """Wrapper for the contains function"""
        return self.contains(key)

    # CONTACT MANAGING FUNCTIONS
    def load_contacts(self, key : str, filename : str, 
                      unlock_method : str) -> ...:
        """
        Load the contacts from the contactbook file.

        Parameters
        ----------
        key : str
            The key to use to decrypt the contactbook.
        filename : str
            The file that is used for the contactbook. If the file does not
            exist, it will be created.
        unlock_method : str
            The method that was used to unlock the contactbook. Can be password
        """
        if not isinstance(key, str):
            raise TypeError("key must be a string, not {}".format(type(key)))
        if not isinstance(filename, (str, type(None))):
            raise TypeError("filename must be a string or None, not {}".format(type(filename)))
        if not isinstance(unlock_method, str):
            raise TypeError("unlock_method must be a string, not {}".format(type(unlock_method)))
        

        if not Utils.file_exists(filename):
            raise ValueError("File {} does not exist.".format(filename))
        
        with open(filename, "rb") as f:
            data = f.read()

        if unlock_method == 'key_file':
            if not Utils.file_exists(key):
                raise ValueError("File {} does not exist.".format(key))
            with open(key, "rb") as f:
                keyring = RsaKeyring(f.read())

            data = keyring.decrypt(data)
        elif unlock_method == 'password':
            data = Utils.decrypt(data, key)

        data = rlp.decode(data)
        self._contacts = {}
        for k, v in data:
            self._contacts[k.decode()] = Contact.decode_rlp(v)
    
    def save_contacts(self, password : str, filename : str, lock_method : str='password') -> ...:
        """
        Save the contacts to the contactbook file.

        Parameters
        ----------
        password : str
            The password to use to encrypt the contactbook. This can also be the filename of 
            a private key file if lock_method is key_file instead of password.
        filename : str
            The file that is used for the contactbook. If the file does not
            exist, it will be created.
        lock_method : str
            The method to use to lock the contactbook. Can be password or key_file.
            Default is password.
        """
        if not isinstance(password, str):
            raise TypeError("password must be a string, not {}".format(type(password)))
        if not isinstance(filename, str):
            raise TypeError("filename must be a string, not {}".format(type(filename)))
        if not isinstance(lock_method, str):
            raise TypeError("lock_method must be a string, not {}".format(type(lock_method)))
        if lock_method.lower() not in ['password', 'key_file']:
            raise ValueError("lock_method must be password or key_file, not {}".format(lock_method))
        # Check if the folder exists
        if not Utils.dir_exists(os.path.dirname(filename)) and os.path.dirname(filename) != '':
            raise ValueError("Folder {} does not exist.".format(os.path.dirname(filename)))
        
        encoded = [[k.encode(), v.encode_rlp()] for k, v in self._contacts.items()]
        data = rlp.encode(encoded)

        if lock_method == 'key_file':
            if not Utils.file_exists(password):
                raise ValueError("File {} does not exist.".format(password))
            keyring = RsaKeyring(key_file=password)
            data = keyring.encrypt(data)
        elif lock_method == 'password':
            data = Utils.encrypt(self._encode_rlp(), password)
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
            raise TypeError("contact must be a Contact object, not {}".format(type(contact)))
        # Check if the nickname already exists
        if contact.nickname in self._contacts.keys():
            raise ContactExistsError(contact.nickname)
        
        self._contacts[contact.nickname] = contact

    def update_contact(self, contact: Contact) -> ...:
        """
        Update a contact in the contactbook.

        Parameters
        ----------
        contact : Contact
            The contact to update in the contactbook.
        """
        if not isinstance(contact, Contact):
            raise TypeError("contact must be a Contact object, not {}".format(type(contact)))
        self._contacts[contact.nickname] = contact

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
        del self._contacts[nickname]

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
        return self._contacts[nickname]
    
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
            raise TypeError("key must be a string, not {}".format(type(nickname)))
        return nickname in self._contacts.keys()

    # CODEC
    def _encode_rlp(self) -> bytes:
        """
        Encode the ContactBook object as an RLP byte string.

        Returns
        -------
        bytes
            The ContactBook object encoded as an RLP string.
        """
        res = [[k.encode(), v.encode_rlp()] for k, v in self._contacts.items()]
        return rlp.encode(res)