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


class HybridCryptoMixin(object):
    block_size = 16
    header_size = 4  # Encrypted message header size (in bytes)
    long_message_threshold = (2048 / 8) - 41  # When message can't be encryted
                                              # using only PKC and hybrid mode
                                              # is used
    aes_key_size = 256 / 8  # Size of the generated AES key (in bytes)
    delimiter = ':'

    def _pad_data(self, data):
        """
        Pad provided data using PKCS#7.
        """
        # Data needs to be padded with at least 1 byte
        pad_len = self.block_size - (len(data) % self.block_size)
        pad_byte = chr(pad_len)
        pad_value = pad_len * pad_byte

        padded_data = data + pad_value
        return padded_data

    def _unpad_data(self, data):
        """
        Unpad provided data using PKCS#7.
        """
        pad_len = ord(data[-1])

        if pad_len > len(data):
            raise ValueError('Corrupted data')

        unpadded_data = data[:-pad_len]
        return unpadded_data

    def _get_header(self, data):
        """
        Return header from the provided data.
        """
        if len(data) < self.header_size:
            raise ValueError('Corrupted data - missing or invalid header')

        header = data[:self.header_size]
        return header

    def _remove_header(self, data):
        """
        Remove header from the provided data.
        """
        if len(data) < self.header_size:
            raise ValueError('Corrupted data - missing or invalid header')

        data = data[self.header_size:]
        return data
