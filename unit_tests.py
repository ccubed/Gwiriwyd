import unittest
from otpy.hotp import hotp
from otpy.totp import totp

class TestHotp(unittest.TestCase):
    def setUp(self):
        self.expected = [755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489]
        self.instance = hotp("12345678901234567890", 0, 6)

    def test_rfc4226(self):
        for x in range(10):
            self.assertEqual(self.instance.at(x), str(self.expected[x]))

        for x in range(10):
            self.assertEqual(self.instance.next(), str(self.expected[x]))

        for x in range(10):
            self.assertTrue(self.instance.verify(str(self.expected[x]), x))

        self.assertEqual(self.instance.drift(3, 1, 1), ['359152', '969429', '338314'])

class TestTotp(unittest.TestCase):
    def setUp(self):
        self.instance = totp("12345678901234567890", 15108406016, 30, 8)

    def test_rfc6238_sha1(self):
        self.assertTrue(self.instance.verify_seconds("94287082", 59))
        self.assertTrue(self.instance.verify_seconds("07081804", 1111111109))
        self.assertTrue(self.instance.verify_seconds("14050471", 1111111111))
        self.assertTrue(self.instance.verify_seconds("89005924", 1234567890))
        self.assertTrue(self.instance.verify_seconds("69279037", 2000000000))
        self.assertTrue(self.instance.verify_seconds("65353130", 20000000000))
