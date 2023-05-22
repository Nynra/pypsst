

class ContactExistsError(Exception):
    """Raised when a contact already exists in the address book"""

    def __init__(self, contact):
        self.contact = contact

    def __str__(self):
        return 'Contact {} already exists'.format(self.contact)
    

class ContactNotFoundError(Exception):
    """Raised when a contact is not found in the address book"""

    def __init__(self, contact):
        self.contact = contact

    def __str__(self):
        return 'Contact {} not found'.format(self.contact)