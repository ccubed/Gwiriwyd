import hashlib
import hmac
import struct

class hotp:
    '''
        Interface to an HOTP RFC 4226 Implementation.
    '''
    def __init__(self, secret : str, counter : int, digits : int):
        '''
            Initialize the interface.

            :param secret str: The Secret Key
            :param counter int: Our initial counter value
            :param digits int: The expected size of the final HOTP Key
        '''
        if len(secret) < 16:
            raise SyntaxError("Per RFC 4226, the smallest possible secret is 16 bytes (128 bits). The RFC recommends 20 bytes (160 bits). Please ask your provider to give you another secret.")
        self.secret = secret.encode()

        if not isinstance(counter, int):
            raise SyntaxError("Counter must be an integer.")
        self.counter = counter

        if digits < 6:
            raise SyntaxError("Per RFC 4226, the smallest possible HOTP Code is 6 digits. Please ask your provider to change their settings.")
        self.digits = digits

    def _generate(self, count : int):
        '''
            Internal function for the actual code generation.

            :param count int: The counter value we're at
        '''
        hresult = hmac.new(self.secret, struct.pack(">Q", count), "sha1").digest()
        offset = hresult[-1] & 0xF
        bin_code = bytearray()
        bin_code.append(hresult[offset] & 0x7F)
        bin_code.append(hresult[offset+1] & 0xFF)
        bin_code.append(hresult[offset+2] & 0xFF)
        bin_code.append(hresult[offset+3] & 0xFF)
        return str(int(bin_code.hex(), 16))[-self.digits:]

    def at(self, count : int):
        '''
            Generate the HOTP code for a given counter value. Please note that this function DOES NOT increment the internal counter.

            :param count int: The counter value to generate a code for
        '''
        return self._generate(count)

    def next(self):
        '''
            Generate the next HOTP code based on the internal counter and increment the internal counter.
        '''
        result = self._generate(self.counter)
        self.counter += 1
        return result

    def verify(self, code : str, count : int):
        '''
            Given a code and the counter value it should be returned at, verify that the code given does in fact match the HOTP code generated at that counter value given the current secret.

            :param code str: The code returned at the specified counter value
            :param count int: The counter value the code is returned at
        '''
        return str(code) == self.at(count)

    def drift(self, initial_count : int, backwards : int = 0, forwards : int = 0, increment_counter : bool=False, increment : int=1):
        '''
            Return the set of HOTP Keys corresponding to the set of counters within the range [initial_count-backwards:initial_count+forwards].
            This function is intended for use in accepting HOTP codes, but by default it does not increment the internal counter. If it should, set increment_counter to True.
            By default, if increment_counter is True we will increment the internal counter by 1. You can increment the counter by more than 1 by specifying a custom value for increment.

            :param initial_count int: The counter value to start at
            :param backwards int: How far to drift backwards
            :param forwards int: How far to drift forwards
            :param increment_counter bool: Should we increment the internal counter?
            :param increment int: If we should, by how much?
        '''
        codes = [self.at(x) for x in range(initial_count-backwards, initial_count+forwards+1)]
        if increment_counter:
            self.counter += increment
        return codes

    def sync(self, new_counter : int):
        '''
            Sometimes the counters get out of sync. Use this function to set the internal counter to a new value.

            :param new_counter int: The new value of the internal counter
        '''
        if not isinstance(new_counter, int):
            raise SyntaxError("Counter must be an int.")
        self.counter = new_counter
        return True
