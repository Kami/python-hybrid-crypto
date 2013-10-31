# Licensed to Tomaz Muraus under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# Tomaz muraus licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import unittest
import os.path
from os.path import join as pjoin

from keyczar.util import RandBytes
from mock import patch

from hybrid_crypto.aes import AESCrypto
from hybrid_crypto.crypto import HybridCryptoMixin
from hybrid_crypto.crypto import HybridCryptoEncrypter
from hybrid_crypto.crypto import HybridCryptoDecrypter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Test vectors from
# http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
AES_CBC_TEST_VECTORS = [
    {'key_size': 128/8, 'key': '2b7e151628aed2a6abf7158809cf4f3c', 'iv': '000102030405060708090a0b0c0d0e0f', 'plaintext': '6bc1bee22e409f96e93d7e117393172a', 'ciphertext': '7649abac8119b246cee98e9b12e9197d'},
    {'key_size': 128/8, 'key': '2b7e151628aed2a6abf7158809cf4f3c', 'iv': '7649abac8119b246cee98e9b12e9197d', 'plaintext': 'ae2d8a571e03ac9c9eb76fac45af8e51', 'ciphertext': '5086cb9b507219ee95db113a917678b2'},
    {'key_size': 128/8, 'key': '2b7e151628aed2a6abf7158809cf4f3c', 'iv': '5086cb9b507219ee95db113a917678b2', 'plaintext': '30c81c46a35ce411e5fbc1191a0a52ef', 'ciphertext': '73bed6b8e3c1743b7116e69e22229516'},
    {'key_size': 128/8, 'key': '2b7e151628aed2a6abf7158809cf4f3c', 'iv': '73bed6b8e3c1743b7116e69e22229516', 'plaintext': 'f69f2445df4f9b17ad2b417be66c3710', 'ciphertext': '3ff1caa1681fac09120eca307586e1a7'},

    {'key_size': 256/8, 'key': '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'iv': '000102030405060708090a0b0c0d0e0f', 'plaintext': '6bc1bee22e409f96e93d7e117393172a', 'ciphertext': 'f58c4c04d6e5f1ba779eabfb5f7bfbd6'},
    {'key_size': 256/8, 'key': '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'iv': 'f58c4c04d6e5f1ba779eabfb5f7bfbd6', 'plaintext': 'ae2d8a571e03ac9c9eb76fac45af8e51', 'ciphertext': '9cfc4e967edb808d679f777bc6702c7d'},
    {'key_size': 256/8, 'key': '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'iv': '9cfc4e967edb808d679f777bc6702c7d', 'plaintext': '30c81c46a35ce411e5fbc1191a0a52ef', 'ciphertext': '39f23369a9d9bacfa530e26304231461'},
    {'key_size': 256/8, 'key': '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4', 'iv': '39f23369a9d9bacfa530e26304231461', 'plaintext': 'f69f2445df4f9b17ad2b417be66c3710', 'ciphertext': 'b2eb05e2c39be9fcda6c19078c6a9d1b'},
]


class HybridCryptoMixinTestCase(unittest.TestCase):
    def test_pad_and_unpad_data(self):
        cls = HybridCryptoMixin()
        cls.block_size = 16

        values = [
            'abcd',  # 4 bytes
            'abcertyuio',  # 10 bytes
            'aaaaaaaaaaaaaaaa',  # 16 bytes
            '123456789',  # 9 bytes
        ]

        padding_chars = [
            chr(12),  # 16 - 4
            chr(6),  # 16 - 10
            chr(16),  # 16 - 16, needs to be at least one so it's rounded to 16
            chr(7)  # 16 - 9
        ]

        for unpadded, padding_char in zip(values, padding_chars):
            padded = cls._pad_data(data=unpadded)
            pad_len = int(ord(padding_char))

            pad_value = (padding_char * pad_len)
            expected = unpadded + str(pad_value)
            unpadded_expected = cls._unpad_data(data=padded)

            self.assertEqual(padded, expected)
            self.assertEqual(unpadded, unpadded_expected)

    def test_RandBytes_size(self):
        sizes = range(0, 100)
        for size in sizes:
            data = RandBytes(n=size)
            self.assertEqual(len(data), size)


class AESCryptoTestCase(unittest.TestCase):
    @patch('hybrid_crypto.aes.RandBytes')
    def test_aes_encrypt(self, mock_func):
        aes = AESCrypto()

        for item in AES_CBC_TEST_VECTORS:
            key = item['key'].decode('hex')
            iv = item['iv'].decode('hex')
            plain_text = item['plaintext'].decode('hex')
            expected_cipher_text = item['ciphertext'].decode('hex')

            mock_func.return_value = iv

            encrypted_with_iv_and_pad = aes.encrypt(key=key, data=plain_text)

            # Remove IV
            encrypted = encrypted_with_iv_and_pad[len(iv):]

            # Unpad
            encrypted = encrypted[:-len(plain_text)]

            self.assertEqual(encrypted, expected_cipher_text)

            # Also test round-trip
            decrypted = aes.decrypt(key=key, data=encrypted_with_iv_and_pad)
            self.assertEqual(decrypted, plain_text)

    def test_aes_decrypt(self):
        aes = AESCrypto()

        # Test data is not padded so we assume pad is a no-op
        aes._unpad_data
        aes._unpad_data = lambda data: data

        for item in AES_CBC_TEST_VECTORS:
            key = item['key'].decode('hex')
            iv = item['iv'].decode('hex')
            expected_plain_text = item['plaintext'].decode('hex')
            cipher_text = item['ciphertext'].decode('hex')

            # Decrypt assumes data contains IV and is padded, but test data is
            # not padded
            data = iv + cipher_text
            decrypted = aes.decrypt(key=key, data=data)
            self.assertEqual(decrypted, expected_plain_text)


class HybridCryptoTestCase(unittest.TestCase):
    def setUp(self):
        self._fixtures_dir = pjoin(BASE_DIR, 'fixtures/')

        self._dir1 = pjoin(self._fixtures_dir, 'public/')
        self._dir2 = pjoin(self._fixtures_dir, 'private/')

        self._encrypter = HybridCryptoEncrypter(keys_path=self._dir1)
        self._decrypter = HybridCryptoDecrypter(keys_path=self._dir2)

    def test_aes_encrypt_and_decrypt_round_trip(self):
        test_data = [
            'foo',
            'foo bar ponies',
            'ponies bar foo ponies',
            'abcd12345'
            'test99',
            'a' * 500 + 'b' * 500 + 'c' * 1000
        ]

        key = RandBytes(n=(256/8))

        for plain_text in test_data:
            encrypted = self._encrypter._aes_encrypt(key=key, data=plain_text)
            self.assertNotEqual(encrypted, plain_text)

            decrypted = self._decrypter._aes_decrypt(key=key, data=encrypted)
            self.assertEqual(decrypted, plain_text)

    def test_encrypt_and_decrypt_round_trip(self):
        test_data = [
            # Short messages (only public-key cryptography is used)
            'foo',
            'foo bar ponies',
            'ponies bar foo ponies',
            'abcd12345'
            'test99',
            'a' * 214,  # 2048 / 8 - 41

            # Long messages (PKC + AES CBC is used)
            'a' * 500 + 'b' * 500 + 'c' * 500,
            'test' * 100
        ]

        for data in test_data:
            encrypted = self._encrypter.encrypt(data=data)
            self.assertNotEqual(encrypted, data)

            decrypted = self._decrypter.decrypt(data=encrypted)
            self.assertEqual(decrypted, data)

if __name__ == '__main__':
    sys.exit(unittest.main())
