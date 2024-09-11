import sys, os
#Following lines are for assigning parent directory dynamically.
dir_path = os.path.dirname(os.path.realpath(__file__))
parent_dir_path = os.path.abspath(os.path.join(dir_path, os.pardir))
sys.path.insert(0, parent_dir_path)

from tools import RsaKeyring, EccKeyring

## RSA
# Create a new keyring
keyring = RsaKeyring()

# Sign and verify a message
message = b"Hello World"
signature = keyring.sign(message)
print("RSA Signature: {}".format(signature))
print("RSA Signature valid: {}".format(keyring.signature_valid(message, signature, keyring.public_key)))

# Verify with new user
new_keyring = RsaKeyring()
print("RSA Signature valid by second: {}".format(new_keyring.signature_valid(message, signature, keyring.public_key)))


## ECC
# Create a new keyring
keyring = EccKeyring()

# Sign and verify a message
message = b"Hello World"
signature = keyring.sign(message)
print("ECC Signature: {}".format(signature))
print("ECC Signature valid: {}".format(keyring.signature_valid(message, signature, keyring.public_key)))

# Verify with new user
new_keyring = EccKeyring()
print("ECC Signature valid by second: {}".format(new_keyring.signature_valid(message, signature, keyring.public_key)))
