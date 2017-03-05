import hashlib
import operator


class otp:
    """
        An interface for RFC 2289 that implements One Time Passwords using MD4 and MD5 in Hex Format.
        **TODO**: 6 Word Format
    """
    def __init__(self, seed : str, secret : str, count : int, hash_algo : str = "md5"):
        """
            Open a new interface to the OTP object.

            :param seed str: The Seed
            :param secret str: The Secret Passphrase
            :param count int: The number of times to run the output through the hashing function
            :param hash_algo str: Which hashing algorithm we're supposed to use. MD4 or MD5
        """
        if not (1 < len(seed) <= 16 and seed.isalnum()):
            raise ValueError("Per RFC 2289, The seed must be between 1-16 alphanumeric characters.")

        if not 10 < len(secret) <= 63:
            raise ValueError("Per RFC 2289, The secret passphrase must be between 10-63 characters.")

        if hash_algo.lower() not in ['md5', 'md4']:
            raise ValueError("MD5 and MD4 are the only supported hashing algorithms.")

        self.hash_lib = hash_algo
        hasher = hashlib.new(hash_algo)
        hasher.update(seed.lower().encode()+secret.encode())

        self.initial = self._fold_md(hasher.digest())
        self.count = count

    def _fold_md(self, data):
        """
            This is a utility function that implements the folding algorithm in RFC 2289 for MD4 and MD5.
        """
        result = bytearray()
        for x in range(8):
            result.append(operator.ixor(data[x], data[x+8]))
        return result

    def _generate(self):
        """
            Internal method that generates the codes
        """
        current = self.initial
        for x in range(self.count):
            hasher = hashlib.new(self.hash_lib)
            hasher.update(current)
            current = self._fold_md(hasher.digest())
        return ' '.join(current.hex()[i:i+4].upper() for i in range(0, len(current.hex()), 4))


    def next(self):
        """
            Generate the next OTP code.
            This function will decrease the internal counter by one.
        """
        if self.count > 0:
            result = self._generate()
            self.count -= 1
            return result
        else:
            raise RuntimeError("This Seed and Secret pair have been exhausted. Please request a new secret or new credentials. If count began at 0 then the key is stored in the initial property.")

    def at(self, count : int):
        """
            Generate the code at count passes of the hash function.
            This function does not modify the internal counter.
        """
        if count > 0:
            current = self.initial
            for x in range(count):
                hasher = hashlib.new(self.hash_lib)
                hasher.update(current)
                current = self._fold_md(hasher.digest())
            return ' '.join(current.hex()[i:i+4].upper() for i in range(0, len(current.hex()), 4))
        else:
            return ' '.join(self.initial.hex()[i:i+4].upper() for i in range(0, len(current.hex()), 4))
