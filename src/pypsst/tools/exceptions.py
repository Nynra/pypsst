

class ContactExistsError(Exception):
    """Raised when a contact already exists in the address book"""

    def __init__(self, nickname : str, msg : str=...) -> ...:
        self.nickname = nickname
        self.msg = msg

    def __str__(self) -> str:
        return 'Contact {} already exists. {}'.format(self.nickname, self.msg)
    

class ContactNotFoundError(Exception):
    """Raised when a contact is not found in the address book"""

    def __init__(self, nickname : str, msg : str=...) -> ...:
        self.nickname = nickname
        if msg is ...:
            msg = ''
        self.msg = msg

    def __str__(self) -> str:
        return 'Contact {} not found. {}'.format(self.nickname, self.msg)
    

class InvalidSignatureError(Exception):
    """Raised when a signature is invalid"""

    def __init__(self, signature : bytes, msg : str=...) -> ...:
        self.signature = signature
        self.msg = msg

    def __str__(self) -> str:
        return 'Signature {} is invalid. {}'.format(self.signature, self.msg)
    

class InvalidCryptoKeyError(Exception):
    """Raised when a cryptographic key is invalid"""

    def __init__(self, key : bytes, msg : str=...) -> ...:
        self.key = key
        if msg is ...:
            msg = ''
        self.msg = msg

    def __str__(self) -> str:
        return 'Key {} is invalid. {}'.format(self.key, self.msg)
