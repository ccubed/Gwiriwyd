[![Build Status](https://travis-ci.org/ccubed/Gwiriwyd.svg?branch=master)](https://travis-ci.org/ccubed/Gwiriwyd)
# Gwiriwyd
I needed to handle One Time Passwords per RFC 4226, 6238 and 2289, but all the libraries on pypi were not valid and returned invalid values per the tests present in the Appendices. Therefore, I set about making my own.

# Current Status
## RFC 2289 - OTP
In Progress

## RFC 4226 - HOTP
Implemented. All tests complete good per the test values in Appendix D of RFC 4426.

## RFC 6238 - TOTP
Partially Implemented. Only supports SHA1 at the moment, but all unit tests completed successfully per the test values in the Appendix.

# Guarantees
## Provide a verification method
All implementations provide a method to verify a key given a specific set of values.

## Provide an at method
Another problem I found with other libraries is that some failed to provide an `at` method. A method which would accept a specific counter or pass phrase and return the result.

## Type Consistency
All the codes are turned as strings so that we don't strip leading zeros.

## Provide a drift method
I only found one implementation with a drift method, even though it's specified in all 3 RFCs that one should exist. You'll find mine conveniently named drift. Mostly for accepting codes, this allows you to easily generate a range of codes so that you can compensate for latency per RFC recommendations.
