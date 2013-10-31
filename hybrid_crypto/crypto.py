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

"""
Abstraction of hybrid-cryptosystem utils on top of Keyczar and pycrypto.
"""

import os.path

from keyczar.keyczar import Encrypter, Crypter
from keyczar.util import Base64WSEncode, Base64WSDecode
from keyczar.util import RandBytes

from hybrid_crypto.utils import HybridCryptoMixin
from hybrid_crypto.aes import AESCrypto

# Valid headers for the encrypted messages
VALID_MESSAGE_HEADERS = [
    'paes',  # Data encrypted using symmetric crypto (AES CBC)
    'hpkc',  # Data encrypted using assymetric crypto (RSA-OAEP)
    'haes',  # Data encrypted using hybrid scheme (RSA-OAEP + AES CBC)
]

__all__ = [
    'HybridCryptoEncrypter',
    'HybridCryptoDecrypter'
]


class HybridCryptoEncrypter(HybridCryptoMixin):
    """
    Class which provides functionality for encrypting data using hybrid
    cryptosystem.
    """

    def __init__(self, keys_path):
        """
        :param keys_path: Path to the directory containg public keys.
        :type keys_path: ``str``
        """
        if not os.path.exists(keys_path):
            raise ValueError('Directory with public keys doesnt exist')

        self._keys_path = keys_path

        self._keyczar = Encrypter.Read(self._keys_path)
        self._aes = AESCrypto()

    def encrypt(self, data):
        """
        Encrypt provided data.
        """
        if len(data) > self.long_message_threshold:
            cipher_text = self._encrypt_long_message(data=data)
        else:
            cipher_text = self._encrypt_short_message(data=data)

        return cipher_text

    def _encrypt_short_message(self, data):
        """
        Encrypt a short message using public-key cryptography.

        :param data: Data to encrypt.
        :type data: ``str``
        """
        header = 'hpkc'
        data = str(data)

        if len(data) > self.long_message_threshold:
            raise ValueError('Data is too long and cant be encrypted using '
                             'PKC')

        cipher_text = header + self._keyczar.Encrypt(data)
        return cipher_text

    def _encrypt_long_message(self, data):
        """
        Encrypt a long message using hybrid cryptography.

        Data is encrypted using the following approach:

        1. Generate fresh symmetric AES key for the data encapsulation scheme
        2. Encrypt provided data using data encapsulation scheme
        3. Encrypt generates AES key using key encapsulation scheme (PKC)
        4. Assemble a final message - header + pkc_encrypted_aes_key +
        delimiter + aes_encrypted_data

        :param data: Data to encrypt.
        :type data: ``str``
        """
        header = 'haes'

        # Generate a fresh symmetric key for the data encapsulation scheme
        aes_key = RandBytes(n=self.aes_key_size)
        aes_key = str(aes_key)

        # Encrypt message using data encapsulation scheme (AES)
        aes_cipher_text = self._aes.encrypt(key=aes_key, data=data)
        aes_cipher_text = Base64WSEncode(aes_cipher_text)

        # Encrypt AES key using key encapsulation scheme
        key_cipher_text = self._keyczar.Encrypt(aes_key)

        # Assemble a final message
        parts = [header, key_cipher_text, self.delimiter, aes_cipher_text]
        msg_cipher_text = ''.join(parts)

        return msg_cipher_text

    def _aes_encrypt(self, key, data):
        header = 'paes'
        cipher_text = self._aes.encrypt(key=key, data=data)

        msg_cipher_text = header + cipher_text
        return msg_cipher_text


class HybridCryptoDecrypter(HybridCryptoMixin):
    def __init__(self, keys_path):
        """
        :param keys_path: Path to the directory containg private keys.
        :type keys_path: ``str``
        """
        if not os.path.exists(keys_path):
            raise ValueError('Directory with private keys doesnt exist')

        self._keys_path = keys_path

        self._keyczar = Crypter.Read(self._keys_path)
        self._aes = AESCrypto()

    def decrypt(self, data):
        """
        Decypt provided data.
        """
        header = self._get_header(data=data)

        if header not in ['hpkc', 'haes']:
            msg = 'Invalid cipher text (missing or corrupted header)'
            raise ValueError(msg)

        if header == 'haes':
            plain_text = self._decrypt_long_message(data=data)
        elif header == 'hpkc':
            plain_text = self._decrypt_short_message(data=data)

        return plain_text

    def _decrypt_short_message(self, data):
        """
        Decrypt a short message.
        """
        data = self._remove_header(data=data)
        plain_text = self._keyczar.Decrypt(data)
        return plain_text

    def _decrypt_long_message(self, data):
        """
        Decrypt a long message.
        """
        data = self._remove_header(data=data)
        delimiter_index = data.rindex(self.delimiter)

        aes_key_cipher_text = data[:delimiter_index]
        aes_key = self._keyczar.Decrypt(aes_key_cipher_text)

        data_cipher_text = data[delimiter_index + 1:]
        data_cipher_text = Base64WSDecode(data_cipher_text)

        plain_text = self._aes.decrypt(key=aes_key, data=data_cipher_text)
        return plain_text

    def _aes_decrypt(self, key, data):
        header = self._get_header(data=data)

        if header != 'paes':
            raise ValueError('Invalid or missing header')

        data = self._remove_header(data=data)
        plain_text = self._aes.decrypt(key=key, data=data)
        return plain_text
