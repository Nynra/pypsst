# class RsaKeyring(AbstractKeyRing):
#     def __init__(self):
#         self._keyring = {}

#     # PROPERTIES
#     @property
#     def key_type(self) -> str:
#         return "RSA"

#     # DUNDER METHODS
#     def __str__(self) -> str:
#         keys = ", ".join(self._keyring.keys())
#         return f"RsaKeyring(keys=[{keys}])"

#     def __repr__(self) -> str:
#         return self.__str__()

#     def __len__(self) -> int:
#         return len(self._keyring)

#     def __hash__(self) -> int:
#         return Utils.hash_data(json.dumpsself._keyring)

#     def __contains__(self, key: str) -> bool:
#         return key in self._keyring

#     def __getitem__(self, key: str) -> RsaKeyPair:
#         return self._keyring[key]

#     def __setitem__(self, key: str, value: RsaKeyPair) -> None:
#         if not isinstance(value, RsaKeyPair):
#             raise ValueError("Value must be an instance of RsaKeyPair")
#         self._keyring[key] = value

#     def __delitem__(self, key: str) -> None:
#         del self._keyring[key]

#     def get_key(self, index: int) -> str:
#         if index < 0 or index >= len(self._keyring):
#             raise IndexError("Index out of range")
#         return list(self._keyring.keys())[index]

#     def set_key(self, name: str, key: str, force: bool = False) -> None:
#         if name in self._keyring and not force:
#             raise ValueError("Key with this name already exists")
#         rsa_key_pair = RsaKeyPair()
#         rsa_key_pair.from_key(key)
#         self._keyring[name] = rsa_key_pair

#     def generate_keypair(self, nickname: str) -> None:
#         rsa_key_pair = RsaKeyPair(nickname)
#         rsa_key_pair.generate_keypair()
#         self._keyring[nickname] = rsa_key_pair

#     def from_key(self, file: str, nickname: str) -> None:
#         rsa_key_pair = RsaKeyPair(nickname)
#         rsa_key_pair.from_key(file)
#         self._keyring[nickname] = rsa_key_pair

#     def sign(self, nickname: str, data: bytes) -> bytes:
#         return self._keyring[nickname].sign(data)

#     def signature_valid(self, nickname: str, data: bytes, signature: bytes) -> bool:
#         return self._keyring[nickname].signature_valid(data, signature)

#     def encrypt(self, nickname: str, data: bytes) -> bytes:
#         receiver_public_key = self._keyring[nickname].public_key
#         return self._keyring[nickname].encrypt(data, receiver_public_key)

#     def decrypt(self, nickname: str, data: bytes) -> bytes:
#         return self._keyring[nickname].decrypt(data, self._keyring[nickname].public_key)
