import hashlib
import hmac
import math
import struct
import time
import warnings
from .hotp import *

class totp(hotp):
    '''
        Interface to a TOTP RFC 6238 Implementation.
    '''
    def __init__(self, secret : str, initial_time : float, time_delta : int, digits : int):
        '''
            Initialize the interface.

            :param secret str: The Secret Key
            :param initial_time float: The unix time at which to start generating time based tokens
            :param time_delta int: The time step in seconds for which each token lasts
            :param digits int: The expected size of the final TOTP Key
        '''
        super().__init__(secret, 0, digits)

        if initial_time <= 0:
            raise SyntaxError("Initial Time must be > 0.")
        self.initial_time = initial_time

        if time_delta < 30:
            warnings.warn("Per RFC 6238, Time Delta's below 30 seconds are not acceptable and insecure. This module will continue but heavily suggests you ask the provider to change their settings.")
        self.time_delta = time_delta

    def at(self, unix_timestamp : float):
        '''
            Generate the TOTP code that would have been returned at a given time.

            :param unix_timestamp float: The unix time at which we're calculating the TOTP
        '''
        return self._generate(math.floor((unix_timestamp - self.initial_time)/self.time_delta))

    def next(self):
        '''
            Generate the next TOTP code based on the internal time step.
        '''
        return self._generate(math.floor((time.time() - self.initial_time)/self.time_delta))

    def verify_timestamp(self, code : str, unix_timestamp : float):
        '''
            Given a code and a unix time, verify that the code matches the one generated for that time.

            :param code str: The code returned at the specified time
            :param unix_timestamp float: The unix time at which the code should be generated
        '''
        return str(code) == self._generate(math.floor((unix_timestamp - self.initial_time)/self.time_delta))

    def verify_seconds(self, code : str, seconds_passed : int):
        '''
            Given a code and the number of seconds past the initial_time, verify that the code would have been generated at this time step.

            :param code str: The code generated at that time step
            :param seconds_passed int: Seconds passed since the initial_time
        '''
        return str(code) == self._generate(math.floor(seconds_passed/self.time_delta))

    def drift(self, initial_count : int, backwards : int = 0, forwards : int = 0):
        '''
            Return the set of TOTP Keys corresponding to the set of time steps within the range [initial_count-backwards:initial_count+forwards].

            :param initial_count int: The counter value to start at
            :param backwards int: How far to drift backwards
            :param forwards int: How far to drift forwards
        '''
        codes = [self.at(x) for x in range(initial_count-backwards, initial_count+forwards+1)]
        return codes

    def get_timestep(self):
        '''
            Utility function to return the current time step.
        '''
        return math.floor((time.time() - self.initial_time)/self.time_delta)
