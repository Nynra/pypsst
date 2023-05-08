"""
A simple command line interface for PyPSST.

This module contains the command line interface for PyPSST. The CLI can
be used to encrypt and decrypt files using the PyPSST library.
"""
from .tools import RsaKeyring, Utils
from .tools.contactbook import ContactBook, Contact
import click
from .config import Config
import os

# Create a decorator for passing the config object to the commands
pass_config = click.make_pass_decorator(Config, ensure=True)


@click.group()
def cli():
    """A simple command line interface for PyPSST."""
    pass

@cli.command()
@click.option(
    "--message",
    "-m",
    type=str,
    required=True,
    help="The message to sign," "this can be a file or a string.",
)
@click.option(
    "--keyfile",
    "-k",
    type=str,
    required=True,
    help="The keyfile to use for signing the file.",
)
def sign(message, keyfile):
    """Sign a file using a private key."""
    # Check if the message is a file or a string
    if not Utils.file_exists(message):
        click.echo("Message is not a file, assuming it is a string.")
        data = message.encode()
    else:
        with open(message, "rb") as f:
            data = f.read()

    # Sign the data
    keyring = RsaKeyring(keyfile)
    signature = keyring.sign(data).decode()
    click.echo(signature)


@cli.command()
@click.option(
    "--message",
    "-m",
    type=str,
    required=True,
    help="The message to verify, " "this can be a file or a string.",
)
@click.option(
    "--signature",
    "-s",
    type=str,
    required=True,
    help="The signature to use for verifying the file.",
)
@click.option(
    "--public-key",
    "-p",
    type=str,
    required=True,
    help="The public key to use for verifying the file.",
)
def verify_signature(message, signature, public_key):
    """Verify the signature of a file using a public key."""
    # Check if the message is a file or a string
    if not Utils.file_exists(message):
        click.echo("Message is not a file, assuming it is a string.")
        data = message.encode()
    else:
        with open(message, "rb") as f:
            data = f.read()

    return RsaKeyring.signature_valid(data, signature, public_key)


@cli.command()
@click.option(
    "--message",
    "-m",
    type=str,
    required=True,
    help="The message to encrypt, this can be a file or a string.",
)
@click.option(
    "--keyfile",
    "-k",
    type=str,
    required=True,
    help="The keyfile to use for encrypting the file.",
)
def encrypt(message, keyfile):
    """Encrypt a file using a public key."""
    # Check if the message is a file or a string
    if not Utils.file_exists(message):
        click.echo("Message is not a file, assuming it is a string.")
        data = message.encode()
    else:
        with open(message, "rb") as f:
            data = f.read()

    # Encrypt the data
    keyring = RsaKeyring(keyfile)
    encrypted_data = keyring.encrypt(data)
    click.echo(encrypted_data)


@cli.command()
@click.option(
    "--message",
    "-m",
    type=str,
    required=True,
    help="The message to decrypt," "this can be a file or a string.",
)
@click.option(
    "--keyfile",
    "-k",
    type=str,
    required=True,
    help="The keyfile to use for decrypting the file.",
)
def decrypt(message, keyfile):
    """Decrypt a file using a private key."""
    # Check if the message is a file or a string
    if not Utils.file_exists(message):
        click.echo("Message is not a file, assuming it is a string.")
        data = message.encode()
    else:
        with open(message, "rb") as f:
            data = f.read()

    # Decrypt the data
    keyring = RsaKeyring(keyfile)
    decrypted_data = keyring.decrypt(data)
    click.echo(decrypted_data)


# Create a group to handle contactbook functions
@cli.group()
@pass_config
def contactbook(config):
    """Manage the contactbook."""
    pass


@contactbook.command()
@click.option(
    "--password",
    "-p",
    type=str,
    required=True,
    help="The password to use to encrypt and decrypt the contactbook.",
)
@click.option(
    "--filename",
    "-f",
    type=str,
    required=False,
    help="The file that is used for the contactbook. If the file does not"
    "exist, it will be created. The default is '.contactbook' in the module folder.",
)
@pass_config
def create(config, password, filename):
    """
    Create a new contactbook.
    """
    # Check if the filename was given
    if filename is None:
        filename = config.get("contactbook", "filename")

    # Check if the contactbook already exists
    if Utils.file_exists(filename):
        click.echo("Contactbook already exists.")
        
        # Ask the user if the contactbook should be overwritten
        click.echo("Do you want to overwrite the contactbook? [y/N]")
        answer = input()
        if answer.lower() != 'y':
            click.echo("Aborting.")
            return

    # Create a new contactbook
    contactbook = ContactBook(password, filename)
    contactbook.save_contacts(password, filename)
    click.echo("Contactbook created.")


@contactbook.command()
@click.option(
    "--password",
    "-p",
    type=str,
    required=True,
    help="The password to use to encrypt and decrypt the contactbook.",
)
@click.option(
    "--filename",
    "-f",
    type=str,
    required=False,
    help="The file that is used for the contactbook. If the file does not"
    "exist, it will be created. The default is '.contactbook' in the module folder.",
)
@pass_config
def add(config, password, filename):
    """
    Add a new contact to the contactbook.
    """
    # Check if the filename was given
    if filename is None:
        filename = config.get("contactbook", "filename")

    # Check if the contactbook exists
    if not Utils.file_exists(filename):
        click.echo("Contactbook does not exist.")
        return

    # Load the contactbook
    contactbook = ContactBook(password, filename)

    # Ask the user for the nickname
    click.echo("Enter the nickname of the contact:")
    nickname = input()

    # Check if the nickname already exists
    if nickname in contactbook.keys():
        click.echo("Nickname already exists.")
        return

    # Ask the user for the public key
    click.echo("Enter the public key of the contact:")
    public_key = input()

    # Create a new contact
    contact = Contact(nickname, public_key)
    contactbook.contacts[nickname] = contact

    # Ask if there are any other attributes that should be added
    while True:
        click.echo("Do you want to add another attribute? [y/N]")
        answer = input()
        if answer.lower() != "y":
            break

        # Ask the user for the attribute name
        click.echo("Enter the attribute name:")
        attribute_name = input()

        # Ask the user for the attribute value
        click.echo("Enter the attribute value:")
        attribute_value = input()

        # Add the attribute to the contact
        contactbook.contacts[nickname][attribute_name] = attribute_value

    # Echo the new contact and ask the user if the input was correct
    click.echo("The new contact is:")
    click.echo(contactbook.contacts[nickname])
    click.echo("Is this correct? [y/N]")
    answer = input()
    if answer.lower() != "y":
        click.echo("Aborting.")
        return

    contactbook.save_contacts(password, filename)


@contactbook.command()
@click.option(
    "--password",
    "-p",
    type=str,
    required=True,
    help="The password to use to encrypt and decrypt the contactbook.",
)
@click.option(
    "--filename",
    "-f",
    type=str,
    required=False,
    help="The file that is used for the contactbook. If the file does not"
    "exist, it will be created. The default is '.contactbook' in the module folder.",
)
@pass_config
def remove(config, password, filename):
    """
    Remove a contact from the contactbook.
    """
    # Check if the filename was given
    if filename is None:
        filename = config.get("contactbook", "filename")

    # Check if the contactbook exists
    if not Utils.file_exists(filename):
        click.echo("Contactbook does not exist.")
        return

    # Load the contactbook
    contactbook = ContactBook(password, filename)

    # Ask the user for the nickname
    click.echo("Enter the nickname of the contact:")
    nickname = input()

    # Check if the nickname exists
    if nickname not in contactbook.keys():
        click.echo("Nickname does not exist.")
        return

    # Remove the contact
    del contactbook.contacts[nickname]
    contactbook.save_contacts(password, filename)


@contactbook.command()
@click.option(
    "--password",
    "-p",
    type=str,
    required=True,
    help="The password to use to encrypt and decrypt the contactbook.",
)
@click.option(
    "--filename",
    "-f",
    type=str,
    required=False,
    help="The file that is used for the contactbook. If the file does not"
    "exist, it will be created. If none is given the file in the config will be used.",
)
@pass_config
def list(config, password, filename):
    """
    List all contacts in the contactbook.

    This command lists all contacts in the contactbook. For
    security reasons, only the nickname of the contact is
    printed. To print all attributes of a contact, use the
    'show' command.
    """
    # Check if the filename is given
    if filename is None:
        filename = config.get("contactbook", "filename")

    # Check if the contactbook exists
    if not Utils.file_exists(filename):
        click.echo("Contactbook does not exist.")
        return
    
    # Check if the path to the file exists
    if not Utils.dir_exists(os.path.dirname(filename)):
        click.echo("Folder {} does not exist.".format(os.path.dirname(filename)))
        return

    # Load the contactbook
    contactbook = ContactBook(password, filename)

    # Print the contacts
    for contact in contactbook.contacts.keys():
        click.echo(contact)
    

@contactbook.command()
@click.option(
    "--password",
    "-p",
    type=str,
    required=True,
    help="The password to use to encrypt and decrypt the contactbook.",
)
@click.option(
    "--filename",
    "-f",
    type=str,
    required=False,
    help="The file that is used for the contactbook. If the file does not"
    "exist, it will be created. If none is given the file in the config will be used.",
)
@click.option(
    "--nickname",
    "-n",
    type=str,
    required=True,
    help="The nickname of the contact to show.",
)
@pass_config
def show(config, password, filename, nickname):
    """
    Show a contact from the contactbook.

    This command shows all attributes of a contact in the
    contactbook. The attributes are printed as a dictionary.
    """
    # Check if the filename is given
    if filename is None:
        filename = config.get("contactbook.DEFAULT", "filename")

    # Check if the contactbook exists
    if not Utils.file_exists(filename):
        click.echo("Contactbook does not exist.")
        return

    # Load the contactbook
    contactbook = ContactBook(password, filename)

    # Check if the nickname exists
    if nickname not in contactbook.keys():
        click.echo("Nickname does not exist.")
        return

    # Print the contact
    click.echo(contactbook.contacts[nickname])

