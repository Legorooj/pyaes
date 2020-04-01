# ----------------------------------------------------------------------------- #
# Copyright (c) 2020 Legorooj <legorooj@pm.me>. This file is licensed under the #
# MIT license. See the LICENSE file in the root of this repository for details. #
# ----------------------------------------------------------------------------- #
from ._mode_base import (
    _EncryptorOFB, _EncryptorCFB, _EncryptorCBC, _EncryptorECB, _EncryptorCTR,
    _DecryptorOFB, _DecryptorECB, _DecryptorCFB, _DecryptorCBC, _DecryptorCTR
)

__all__ = ['AES_CBC', 'AES_CFB', 'AES_CTR', 'AES_ECB', 'AES_OFB']


class AES_ECB:
    def __init__(self, key):
        if not isinstance(key, bytes):
            raise TypeError('key must be bytes')
        if len(key) not in (16, 24, 32):
            raise ValueError('invalid key length for aes')
        self._key = key
        
    def encryptor(self):
        return _EncryptorECB(self._key)

    def decryptor(self):
        return _DecryptorECB(self._key)


class AES_CBC:
    
    def __init__(self, key, iv):
        if not isinstance(key, bytes):
            raise TypeError('key must be bytes')
        if len(key) not in (16, 24, 32):
            raise ValueError('invalid key length for aes')
        if not isinstance(iv, bytes):
            raise TypeError('iv must be bytes')
        if len(iv) != 16:
            raise ValueError('iv must be 128 bits (16 bytes) long')
        
        self._key = key
        self._iv = iv
        
    def encryptor(self):
        return _EncryptorCBC(self._key, self._iv)

    def decryptor(self):
        return _DecryptorCBC(self._key, self._iv)
        

class AES_CTR:
    
    def __init__(self, key, nonce):
        if not isinstance(key, bytes):
            raise TypeError('key must be bytes')
        if len(key) not in (16, 24, 32):
            raise ValueError('invalid key length for aes')
        if not isinstance(nonce, bytes):
            raise TypeError('nonce must be bytes')
        if len(nonce) != 16:
            raise ValueError('nonce must be 128 bits (16 bytes) long')

        self._key = key
        self._nonce = nonce

    def encryptor(self):
        return _EncryptorCTR(self._key, self._nonce)

    def decryptor(self):
        return _DecryptorCTR(self._key, self._nonce)


class AES_CFB:
    
    def __init__(self, key, iv):
        if not isinstance(key, bytes):
            raise TypeError('key must be bytes')
        if len(key) not in (16, 24, 32):
            raise ValueError('invalid key length for aes')
        if not isinstance(iv, bytes):
            raise TypeError('iv must be bytes')
        if len(iv) != 16:
            raise ValueError('iv must be 128 bits (16 bytes) long')
        
        self._key = key
        self._iv = iv

    def encryptor(self):
        return _EncryptorCFB(self._key, self._iv)

    def decryptor(self):
        return _DecryptorCFB(self._key, self._iv)


class AES_OFB:
    
    def __init__(self, key, iv):
        """
        Class providing AES_OFB encryption utilities.
        :param bytes key:
        :param bytes iv:
        """
        if not isinstance(key, bytes):
            raise TypeError('key must be bytes')
        if len(key) not in (16, 24, 32):
            raise ValueError('invalid key length for aes')
        if not isinstance(iv, bytes):
            raise TypeError('iv must be bytes')
        if len(iv) != 16:
            raise ValueError('iv must be 128 bits (16 bytes) long')
        
        self._key = key
        self._iv = iv

    def encryptor(self):
        return _EncryptorOFB(self._key, self._iv)

    def decryptor(self):
        return _DecryptorOFB(self._key, self._iv)
