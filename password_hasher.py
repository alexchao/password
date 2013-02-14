# -*- coding: utf-8 -*-
import binascii
import hashlib
import hmac
from collections import namedtuple
import os


PasswordStorables = namedtuple('PasswordStorables', 'hmac salt')


class PasswordHasher(object):

    def __init__(self, hmac_key, salt_length):
        self._hmac_key = hmac_key
        self._salt_length = salt_length

    def hash(self, password):
        salt = self._generate_salt()
        code = self._make_hmac(salt, password)
        return PasswordStorables(code, salt)

    def _make_hmac(self, salt, password):
        salted_password = self._add_salt(salt, password)
        pw_hmac = hmac.new(self._hmac_key, salted_password, hashlib.sha1)
        return binascii.hexlify(pw_hmac.digest())

    def _generate_salt(self):
        return binascii.hexlify(os.urandom(self._salt_length))

    @staticmethod
    def _add_salt(salt, password):
        return salt + password

