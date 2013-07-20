# -*- coding: utf-8 -*-
import unittest

from password_hasher import PasswordHasher


class HashPasswordTest(unittest.TestCase):

    def test_hash_and_check(self):
        password = 'liloupockemoncrew'
        hasher = PasswordHasher(hmac_key='alexchao', salt_length=20)
        storables = hasher.hash(password)
        assert not hasher.check(
            'liloupokemoncrew',
            storables.salt,
            storables.hmac)
        assert hasher.check(
            password,
            storables.salt,
            storables.hmac)


if __name__ == '__main__':
    unittest.main()
