import unittest
from gwiriwyd.hotp import hotp

class TestHotp(unittest.TestCase):
    def setUp(self):
        self.expected = [755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489]
        self.instance = hotp("12345678901234567890", 0, 6)

    def test_rfc4226(self):
        for x in range(10):
            self.assertEqual(self.instance.at(x), self.expected[x])
