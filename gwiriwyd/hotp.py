import hashlib
import hmac
import struct

class hotp:
    def __init__(self, secret, counter, digits):
        self.secret = secret.encode()
        self.counter = counter
        self.digits = digits

    def _generate(self, count):
        hresult = hmac.new(self.secret, struct.pack(">Q", count), "sha1").digest()
        offset = hresult[-1] & 0xF
        bin_code = bytearray()
        bin_code.append(hresult[offset] & 0x7F)
        bin_code.append(hresult[offset+1] & 0xFF)
        bin_code.append(hresult[offset+2] & 0xFF)
        bin_code.append(hresult[offset+3] & 0xFF)
        return int(str(int(bin_code.hex(), 16))[-self.digits:])

    def at(self, count):
        return self._generate(count)

    def next(self):
        result = self._generate(self.counter)
        self.counter += 1
        return result

    def verify(self, code, count):
        return int(code) == self.at(count)
