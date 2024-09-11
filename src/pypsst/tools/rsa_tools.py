from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from typing import Any
import json
from .base import AbstractKeyPair, AbstractKeyRing


class RsaKeyPair(AbstractKeyPair):
    def __init__(self, nickname: str = None):
        self._key_pair = None
        self._nickname = nickname

    @property
    def public_key_string(self) -> str:
        return self._key_pair.publickey().export_key().decode('utf-8')

    @property
    def public_key(self) -> bytes:
        return self._key_pair.publickey().export_key()

    @property
    def nickname(self) -> str:
        return self._nickname

    @nickname.setter
    def nickname(self, name: str) -> None:
        self._nickname = name

    def __str__(self) -> str:
        return f"RsaKeyPair(nickname={self._nickname})"

    def __repr__(self) -> str:
        return f"RsaKeyPair(nickname={self._nickname}, public_key={self.public_key_string})"

    def __hash__(self) -> int:
        return hash(self.public_key)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, RsaKeyPair):
            return self.public_key == other.public_key
        return False

    def generate_keypair(self) -> None:
        self._key_pair = RSA.generate(2048)

    def from_key(self, file: str) -> None:
        with open(file, 'rb') as key_file:
            self._key_pair = RSA.import_key(key_file.read())

    def sign(self, data: bytes) -> bytes:
        h = SHA256.new(data)
        signature = pkcs1_15.new(self._key_pair).sign(h)
        return signature

    def signature_valid(self, data: bytes, signature: bytes, public_key: bytes = None) -> bool:
        if public_key is None:
            public_key = self.public_key
        rsa_key = RSA.import_key(public_key)
        h = SHA256.new(data)
        try:
            pkcs1_15.new(rsa_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    def encrypt(self, data: bytes, receiver_public_key: bytes) -> bytes:
        recipient_key = RSA.import_key(receiver_public_key)
        session_key = get_random_bytes(16)

        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        encrypted_data = json.dumps({
            'enc_session_key': enc_session_key.hex(),
            'nonce': cipher_aes.nonce.hex(),
            'tag': tag.hex(),
            'ciphertext': ciphertext.hex(),
            'signature': self.sign(ciphertext).hex()
        }).encode('utf-8')

        return encrypted_data

    def decrypt(self, data: bytes, sender_public_key: bytes = None) -> bytes:
        data = json.loads(data.decode('utf-8'))
        enc_session_key = bytes.fromhex(data['enc_session_key'])
        nonce = bytes.fromhex(data['nonce'])
        tag = bytes.fromhex(data['tag'])
        ciphertext = bytes.fromhex(data['ciphertext'])
        signature = bytes.fromhex(data['signature'])

        if sender_public_key and not self.signature_valid(ciphertext, signature, sender_public_key):
            raise ValueError("Invalid signature.")

        cipher_rsa = PKCS1_OAEP.new(self._key_pair)
        session_key = cipher_rsa.decrypt(enc_session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

        return decrypted_data


class RsaKeyring(AbstractKeyRing):
    def __init__(self):
        self._keyring = {}
        
    @property
    def key_type(self) -> str:
        return "RSA"
    
    def __str__(self) -> str:
        keys = ', '.join(self._keyring.keys())
        return f"RsaKeyring(keys=[{keys}])"
    
    def __repr__(self) -> str:
        return self.__str__()
    
    def __len__(self) -> int:
        return len(self._keyring)
    
    def __contains__(self, key: str) -> bool:
        return key in self._keyring
    
    def __getitem__(self, key: str) -> RsaKeyPair:
        return self._keyring[key]
    
    def __setitem__(self, key: str, value: RsaKeyPair) -> None:
        if not isinstance(value, RsaKeyPair):
            raise ValueError("Value must be an instance of RsaKeyPair")
        self._keyring[key] = value
    
    def __delitem__(self, key: str) -> None:
        del self._keyring[key]
    
    def get_key(self, index: int) -> str:
        if index < 0 or index >= len(self._keyring):
            raise IndexError("Index out of range")
        return list(self._keyring.keys())[index]
    
    def set_key(self, name: str, key: str, force: bool = False) -> None:
        if name in self._keyring and not force:
            raise ValueError("Key with this name already exists")
        rsa_key_pair = RsaKeyPair()
        rsa_key_pair.from_key(key)
        self._keyring[name] = rsa_key_pair
    
    def generate_keypair(self, nickname: str) -> None:
        rsa_key_pair = RsaKeyPair(nickname)
        rsa_key_pair.generate_keypair()
        self._keyring[nickname] = rsa_key_pair
    
    def from_key(self, file: str, nickname: str) -> None:
        rsa_key_pair = RsaKeyPair(nickname)
        rsa_key_pair.from_key(file)
        self._keyring[nickname] = rsa_key_pair
    
    def sign(self, nickname: str, data: bytes) -> bytes:
        return self._keyring[nickname].sign(data)
    
    def signature_valid(self, nickname: str, data: bytes, signature: bytes) -> bool:
        return self._keyring[nickname].signature_valid(data, signature)
    
    def encrypt(self, nickname: str, data: bytes) -> bytes:
        receiver_public_key = self._keyring[nickname].public_key
        return self._keyring[nickname].encrypt(data, receiver_public_key)
    
    def decrypt(self, nickname: str, data: bytes) -> bytes:
        return self._keyring[nickname].decrypt(data, self._keyring[nickname].public_key)
