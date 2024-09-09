import sys, os
#Following lines are for assigning parent directory dynamically.
dir_path = os.path.dirname(os.path.realpath(__file__))
parent_dir_path = os.path.abspath(os.path.join(dir_path, os.pardir))
sys.path.insert(0, parent_dir_path)

from tools import RsaKeyring

## RSA
# Create a new keyring
sender_keyring = RsaKeyring()
receiver_keyring = RsaKeyring()

print('Sender Public Key: {}\n'.format(sender_keyring.public_key))
print('Receiver Public Key: {}\n'.format(receiver_keyring.public_key))


# Encrypt the message for the receiver
message = b"Hello World"
encrypted_message = sender_keyring.encrypt(message, receiver_keyring.public_key)
print('Message: {}'.format(message))
print('Encrypted Message: {}\n'.format(encrypted_message))

# Decrypt the message
decrypted_message = receiver_keyring.decrypt(encrypted_message)
print('Decrypted Message: {}'.format(decrypted_message))