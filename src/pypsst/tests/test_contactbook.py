import unittest
from pypsst import ContactBook, Contact, Utils
import rlp
import os
import json
import random


class TestContactKeyStorgae(unittest.TestCase):
    
    def setUp(self):
        # Create some test keys
        self.test_key_type = "rsa"
        self.authentication_key = random.randbytes(32).hex()
        self.encryption_key = random.randbytes(32).hex()
        super().setUp()

    def test_init(self):
        # Test with default attributes
        contact_key_storage = Contact.KeyStorage(self.test_key_type, self.authentication_key, self.encryption_key)
        self.assertEqual(contact_key_storage.key_type, self.test_key_type)
        self.assertEqual(contact_key_storage.authentication_key, self.authentication_key)
        self.assertEqual(contact_key_storage.encryption_key, self.encryption_key)

        # Test initiating with byte keys
        contact_key_storage = Contact.KeyStorage(self.test_key_type, bytes.fromhex(self.authentication_key), bytes.fromhex(self.encryption_key))
        self.assertEqual(contact_key_storage.key_type, self.test_key_type)
        self.assertEqual(contact_key_storage.authentication_key, self.authentication_key)
        self.assertEqual(contact_key_storage.encryption_key, self.encryption_key)
        

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
        self.assertTrue(contact["attr1"] == "value1")
        self.assertTrue(contact["attr2"] == "value2")

    def test_encode_json(self):
        # Test with default attributes
        expected = {
            "key_type": "MyKeyType",
            "nickname": "MyNickname",
            "public_key": "MyKey",
        }
        contact = Contact("MyNickname", "MyKey", "MyKeyType")
        self.assertEqual(contact.encode_json(), json.dumps(expected))

        # Test with additional attributes
        contact = Contact(
            "MyNickname", "MyKey", "MyKeyType", attr1="value1", attr2="value2"
        )
        expected = {
            "attr1": "value1",
            "attr2": "value2",
            "key_type": "MyKeyType",
            "nickname": "MyNickname",
            "public_key": "MyKey",
        }
        self.assertEqual(contact.encode_json(), json.dumps(expected))

    def test_decode_json(self):
        content = {
            "key_type": "MyKeyType",
            "nickname": "MyNickname",
            "public_key": "MyKey",
        }
        contact = Contact.decode_json(json.dumps(content))

        self.assertEqual(contact.nickname, "MyNickname")
        self.assertEqual(contact.public_key, "MyKey")
        self.assertEqual(contact.key_type, "MyKeyType")

        content = {
            "attr1": "value1",
            "attr2": "value2",
            "key_type": "MyKeyType",
            "nickname": "MyNickname",
            "public_key": "MyKey",
        }
        contact = Contact.decode_json(json.dumps(content))

        self.assertEqual(contact.nickname, "MyNickname")
        self.assertEqual(contact.public_key, "MyKey")
        self.assertEqual(contact.key_type, "MyKeyType")
        self.assertEqual(contact["attr1"], "value1")
        self.assertEqual(contact["attr2"], "value2")

    def test_encode_rlp(self):
        content = {
            "key_type": "MyKeyType",
            "nickname": "MyNickname",
            "public_key": "MyKey",
        }
        contact = Contact("MyNickname", "MyKey", "MyKeyType")
        expected = rlp.encode(json.dumps(content).encode())
        self.assertEqual(contact.encode_rlp(), expected)

        content = {
            "attr1": "value1",
            "attr2": "value2",
            "key_type": "MyKeyType",
            "nickname": "MyNickname",
            "public_key": "MyKey",
        }
        contact = Contact(
            "MyNickname", "MyKey", "MyKeyType", attr1="value1", attr2="value2"
        )
        expected = rlp.encode(json.dumps(content).encode())

    def test_decode_rlp(self):
        content = {
            "key_type": "MyKeyType",
            "nickname": "MyNickname",
            "public_key": "MyKey",
        }
        contact = Contact.decode_rlp(rlp.encode(json.dumps(content).encode()))

        self.assertEqual(contact.nickname, "MyNickname")
        self.assertEqual(contact.public_key, "MyKey")
        self.assertEqual(contact.key_type, "MyKeyType")

        content = {
            "attr1": "value1",
            "attr2": "value2",
            "key_type": "MyKeyType",
            "nickname": "MyNickname",
            "public_key": "MyKey",
        }
        contact = Contact.decode_rlp(rlp.encode(json.dumps(content).encode()))

        self.assertEqual(contact.nickname, "MyNickname")
        self.assertEqual(contact.public_key, "MyKey")
        self.assertEqual(contact.key_type, "MyKeyType")
        self.assertEqual(contact["attr1"], "value1")
        self.assertEqual(contact["attr2"], "value2")


class TestContactBook(unittest.TestCase):
    contactbook_file = "MyFile"
    contactbook_password = "MyPassword"

    def setUp(self):
        self.contactbook = ContactBook(
            filename=self.contactbook_file,
            password=self.contactbook_password,
            create_new=True,
            contact_storage={}
        )
        self.contact = Contact(
            nickname="MyNickname", public_key="MyKey", key_type="MyKeyType"
        )

    def tearDown(self) -> ...:
        # Remove the test files
        if os.path.exists("MyFile"):
            os.remove("MyFile")

        if os.path.exists("./contactbook_test.bn"):
            os.remove("./contactbook_test.bn")

        # Check if the MyPassword file exists
        if os.path.exists("MyPassword"):
            os.remove("MyPassword")
            raise Exception("The password file was not removed")

    # def test_hash(self):
    #     self.assertEqual(
    #         self.contactbook.__hash__(),
    #         int(Utils.hash_data(self.contactbook._encode_rlp()), 16),
    #     )

    # def test_eq(self):
    #     # Test with default attributes
    #     contactbook = ContactBook(
    #         password=self.contactbook_password,
    #         filename=self.contactbook_file,
    #         create_new=True,
    #     )
    #     self.assertEqual(self.contactbook, contactbook)

    def test_iter(self):
        contact2 = Contact(nickname="MyNickname2", public_key="MyKey2", key_type="RSA")
        self.contactbook._contacts = {
            self.contact.nickname: self.contact,
            contact2.nickname: contact2,
        }

        seen1 = False
        seen2 = False
        for stored_contact in self.contactbook:
            if stored_contact == self.contact:
                seen1 = True
            elif stored_contact == contact2:
                seen2 = True

        self.assertTrue(seen1)
        self.assertTrue(seen2)

    def test_len(self):
        self.contactbook._contacts = {self.contact.nickname: self.contact}
        self.assertEqual(len(self.contactbook), 1)

        for i in range(10):
            c = Contact(
                "MyNickname{}".format(i), "MyKey{}".format(i), "MyKeyType{}".format(i)
            )
            self.contactbook._contacts[c.nickname] = c

        self.assertEqual(len(self.contactbook), 11)

    def test_add_one_default_contact(self):
        self.contactbook.add_contact(self.contact)
        self.assertEqual(
            self.contactbook._contacts, {self.contact.nickname: self.contact}
        )

    def test_add_one_additional_contact(self):
        contact = Contact(
            nickname="MyNickname",
            public_key="MyKey",
            key_type="MyKeyType",
            attr1="value1",
            attr2="value2",
        )
        self.contactbook.add_contact(contact)
        self.assertEqual(self.contactbook._contacts, {"MyNickname": contact})

    def test_add_lots_of_default_contacts(self):
        for i in range(100):
            contact = Contact(
                "MyNickname{}".format(i), "MyKey{}".format(i), "MyKeyType{}".format(i)
            )
            self.contactbook.add_contact(contact)

        self.assertEqual(len(self.contactbook._contacts.keys()), 100)

        # Check if all the contacts were added
        for i in range(100):
            self.assertTrue(
                self.contactbook._contacts["MyNickname{}".format(i)]
                == Contact(
                    nickname="MyNickname{}".format(i),
                    public_key="MyKey{}".format(i),
                    key_type="MyKeyType{}".format(i),
                )
            )

    def test_add_lots_of_additional_contacts(self):
        for i in range(100):
            contact = Contact(
                "MyNickname{}".format(i),
                "MyKey{}".format(i),
                "MyKeyType{}".format(i),
                attr1="value{}".format(i),
                attr2="value{}".format(i * 2),
                attr3="value{}".format(i * 3),
            )
            self.contactbook.add_contact(contact)

        self.assertEqual(len(self.contactbook._contacts.keys()), 100)

        # Check if all the contacts were added
        for i in range(100):
            self.assertTrue(
                self.contactbook._contacts["MyNickname{}".format(i)] 
                == Contact(
                    nickname="MyNickname{}".format(i),
                    public_key="MyKey{}".format(i),
                    key_type="MyKeyType{}".format(i),
                    attr1="value{}".format(i),
                    attr2="value{}".format(i * 2),
                    attr3="value{}".format(i * 3),
                )
            )

    def test_save_and_load_contacts(self):
        contracts = []
        for i in range(10):
            contact = Contact(
                nickname="MyNickname{}".format(i), 
                public_key="MyKey{}".format(i), 
                key_type="MyKeyType{}".format(i)
            )
            contracts.append(contact)
            self.contactbook._contacts[contact.nickname] = contact

        self.assertTrue(len(self.contactbook._contacts.keys()), 10)
        self.contactbook.save_contacts(
            filename="./contactbook_test.bn", password="MyPassword"
        )

        # Check if the file was created
        self.assertTrue(os.path.exists("./contactbook_test.bn"))

        # Load the contacts
        contactbook = ContactBook(password="MyPassword", 
                                  filename="./contactbook_test.bn")

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

        self.contactbook.save_contacts(
            filename="./contactbook_test.bn", password="MyPassword"
        )

        # Check if the file was created
        self.assertTrue(os.path.exists("./contactbook_test.bn"))

        # Load the contacts
        contactbook = ContactBook(password="MyPassword", 
                                  filename="./contactbook_test.bn")
        self.assertEqual(len(contactbook._contacts.keys()), 10)
        for contact in contracts:
            self.assertEqual(contactbook._contacts[contact.nickname], contact)

    def test_encode_rlp(self):
        self.contactbook._contacts = {self.contact.nickname: self.contact}
        expected = rlp.encode(
            [
                [k.encode(), v.encode_rlp()]
                for k, v in self.contactbook._contacts.items()
            ]
        )
        self.assertEqual(self.contactbook._encode_rlp(), expected)

    def test_encode_rlp_additional(self):
        contact = Contact(
            "MyNickname", "MyKey", "MyKeyType", attr1="value1", attr2="value2"
        )
        self.contactbook._contacts = {contact.nickname: contact}
        expected = rlp.encode(
            [
                [k.encode(), v.encode_rlp()]
                for k, v in self.contactbook._contacts.items()
            ]
        )
        self.assertEqual(self.contactbook._encode_rlp(), expected)
