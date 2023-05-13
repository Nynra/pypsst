import unittest
from pypsst import ContactBook, Contact, Utils
import rlp
import os


class TestContact(unittest.TestCase):
    def setUp(self):
        self.contact = Contact("MyNickname", "MyKey", "MyKeyType")

    def test_hash(self):
        self.assertEqual(
            self.contact.__hash__(), int(Utils.hash_data(self.contact.encode_rlp()), 16)
        )

    def test_eq(self):
        # Test with default attributes
        contact = Contact("MyNickname", "MyKey", "MyKeyType")
        self.assertEqual(self.contact, contact)

        # Test with additional attributes
        contact = Contact(
            "MyNickname", "MyKey", "MyKeyType", attr1="value1", attr2="value2"
        )
        contact2 = Contact(
            "MyNickname", "MyKey", "MyKeyType", attr1="value1", attr2="value2"
        )
        self.assertTrue(contact2 == contact)

        # Test with different nickname
        contact = Contact("MyNickname2", "MyKey", "MyKeyType")
        self.assertFalse(self.contact == contact)

    def test_setitem_and_getitem(self):
        self.contact["attr1"] = "value1"
        self.assertEqual(self.contact["attr1"], "value1")

        with self.assertRaises(ValueError):
            self.contact["nickname"] = "value1"

    def test_delitem(self):
        self.contact["attr1"] = "value1"
        del self.contact["attr1"]

        with self.assertRaises(KeyError):
            del self.contact["attr1"]

    def test_contains(self):
        self.contact["attr1"] = "value1"
        self.assertTrue("attr1" in self.contact)
        self.assertFalse("attr2" in self.contact)

    def test_init_default_attributes(self):
        self.assertEqual(self.contact.nickname, "MyNickname")
        self.assertEqual(self.contact.public_key, "MyKey")
        self.assertEqual(self.contact.key_type, "MyKeyType")

    def test_init_additional_attributes(self):
        contact = Contact(
            "MyNickname", "MyKey", "MyKeyType", attr1="value1", attr2="value2"
        )
        self.assertEqual(contact.attr1, "value1")
        self.assertEqual(contact.attr2, "value2")

    def test_encode_rlp(self):
        # Test with default attributes
        expected = rlp.encode(
            [[k.encode(), v.encode()] for k, v in self.contact.__dict__.items()]
        )
        self.assertEqual(self.contact.encode_rlp(), expected)

        # Test with additional attributes
        contact = Contact(
            "MyNickname", "MyKey", "MyKeyType", attr1="value1", attr2="value2"
        )
        expected = rlp.encode(
            [[k.encode(), v.encode()] for k, v in contact.__dict__.items()]
        )
        self.assertEqual(contact.encode_rlp(), expected)

    def test_decode_rlp(self):
        # Test with default attributes
        expected = rlp.encode(
            [[k.encode(), v.encode()] for k, v in self.contact.__dict__.items()]
        )
        self.assertTrue(Contact.decode_rlp(expected) == self.contact)

        # Test with additional attributes
        contact = Contact(
            "MyNickname", "MyKey", "MyKeyType", attr1="value1", attr2="value2"
        )
        expected = rlp.encode(
            [[k.encode(), v.encode()] for k, v in contact.__dict__.items()]
        )
        self.assertEqual(Contact.decode_rlp(expected), contact)


class TestContactBook(unittest.TestCase):
    def setUp(self):
        self.contactbook = ContactBook("MyPassword", None)

    def tearDown(self) -> None:
        # Remove the file
        if os.path.exists("MyFile"):
            os.remove("MyFile")


    def test_hash(self):
        self.assertEqual(
            self.contactbook.__hash__(),
            int(Utils.hash_data(self.contactbook._encode_rlp()), 16),
        )

    def test_eq(self):
        # Test with default attributes
        contactbook = ContactBook("MyPassword", None)
        self.assertEqual(self.contactbook, contactbook)

    def test_iter(self):
        # Test with default attributes
        contact = Contact("MyNickname", "MyKey", "MyKeyType")
        self.contactbook.add_contact(contact)

        for contact in self.contactbook:
            self.assertEqual(contact, contact)

    def test_len(self):
        # Test with default attributes
        contact = Contact("MyNickname", "MyKey", "MyKeyType")
        self.contactbook.add_contact(contact)

        self.assertEqual(len(self.contactbook), 1)

        for i in range(10):
            c = Contact("MyNickname{}".format(i), "MyKey{}".format(i), "MyKeyType{}".format(i))
            self.contactbook.add_contact(c)

        self.assertEqual(len(self.contactbook), 11)

    def test_add_one_default_contact(self):
        contact = Contact("MyNickname", "MyKey", "MyKeyType")
        self.contactbook.add_contact(contact)

        self.assertEqual(self.contactbook._contacts, {"MyNickname": contact})

    def test_add_one_additional_contact(self):
        contact = Contact(
            "MyNickname", "MyKey", "MyKeyType", attr1="value1", attr2="value2"
        )
        self.contactbook.add_contact(contact)

        self.assertEqual(self.contactbook._contacts, {"MyNickname": contact})

    def test_add_lots_of_default_contacts(self):
        for i in range(100):
            contact = Contact(
                "MyNickname{}".format(i), "MyKey{}".format(i), "MyKeyType{}".format(i)
            )
            self.contactbook.add_contact(contact)

        self.assertEqual(len(self.contactbook._contacts), 100)

    def test_add_lots_of_additional_contacts(self):
        for i in range(100):
            contact = Contact(
                "MyNickname{}".format(i),
                "MyKey{}".format(i),
                "MyKeyType{}".format(i),
                attr1="value{}".format(i),
                attr2="value{}".format(i*2),
                attr3="value{}".format(i*3),
            )
            self.contactbook.add_contact(contact)

        self.assertEqual(len(self.contactbook._contacts), 100)

    def test_save_and_load_contacts(self):
        contracts = []
        for i in range(10):
            contact = Contact(
                "MyNickname{}".format(i), "MyKey{}".format(i), "MyKeyType{}".format(i)
            )
            contracts.append(contact)
            self.contactbook.add_contact(contact)

        self.assertTrue(len(self.contactbook._contacts.keys()), 10)
        self.contactbook.save_contacts(filename="./contactbook_test.bn", password="MyPassword")

        # Check if the file was created
        self.assertTrue(os.path.exists("./contactbook_test.bn"))
        
        # Load the contacts
        contactbook = ContactBook("MyPassword", "./contactbook_test.bn")

        # Delete the file
        os.remove("./contactbook_test.bn")

        self.assertEqual(len(contactbook._contacts.keys()), 10)
        for contact in contracts:
            self.assertEqual(contactbook._contacts[contact.nickname], contact)

    def test_save_and_load_contacts_with_additional_attributes(self):
        contracts = []
        for i in range(10):
            contact = Contact(
                "MyNickname{}".format(i),
                "MyKey{}".format(i),
                "MyKeyType{}".format(i),
                attr1="value1",
                attr2="value2",
                attr3="value3",
            )
            contracts.append(contact)
            self.contactbook.add_contact(contact)

        self.contactbook.save_contacts(filename="./contactbook_test.bn", password="MyPassword")

        # Check if the file was created
        self.assertTrue(os.path.exists("./contactbook_test.bn"))

        # Load the contacts
        contactbook = ContactBook("MyPassword", "./contactbook_test.bn")
        self.assertEqual(len(contactbook._contacts.keys()), 10)
        for contact in contracts:
            self.assertEqual(contactbook._contacts[contact.nickname], contact)

    def test_encode_rlp(self):
        # Test with default attributes
        contact = Contact("MyNickname", "MyKey", "MyKeyType")
        self.contactbook.add_contact(contact)

        expected = rlp.encode(
            [[k.encode(), v.encode_rlp()] for k, v in self.contactbook._contacts.items()]
        )
        self.assertEqual(self.contactbook._encode_rlp(), expected)