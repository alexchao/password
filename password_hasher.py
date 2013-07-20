# -*- coding: utf-8 -*-
import binascii
import hashlib
import hmac
from collections import namedtuple
import os


PasswordStorables = namedtuple('PasswordStorables', 'hmac salt')


class PasswordHasher(object):
    """Given a HMAC key and salt length, hashes a password and returns
    its storable values: the HMAC and salt.

    The salt is returned in hexadecimal representation. This returned
    value is therefore twice as long as the salt_length provided.

    """

    def __init__(self, hmac_key, salt_length):
        self._hmac_key = hmac_key
        self._salt_length = salt_length

    def hash(self, password):
        salt = self._generate_salt()
        code = self._make_hmac(salt, password)
        return PasswordStorables(code, salt)

    def check(self, password, salt, hmac):
        return hmac == self._make_hmac(salt, password)

    def _make_hmac(self, salt, password):
        # XXX: maybe its own class
        salted_password = self._add_salt(salt, password)
        pw_hmac = hmac.new(self._hmac_key, salted_password, hashlib.sha1)
        return binascii.hexlify(pw_hmac.digest())

    def _generate_salt(self):
        return binascii.hexlify(os.urandom(self._salt_length))

    @staticmethod
    def _add_salt(salt, password):
        return salt + password
