# ----------------------------------------------------------------------------- #
# Copyright (c) 2020 Legorooj <legorooj@pm.me>. This file is licensed under the #
# MIT license. See the LICENSE file in the root of this repository for details. #
# ----------------------------------------------------------------------------- #
# cython: language_level=3
from ._aes_base cimport AESBase


cdef class _Counter:
    cdef readonly bytearray value

    def __cinit__(self, nonce):
        """Counter object for CTR mode.
        Custom counters can be created by subclassing and overriding the *inc* method"""
        self.value = bytearray(nonce)

    cpdef void inc(self):
        """Increment the counter"""
        cdef int i
        for i in range(len(self.value) - 1, -1, -1):

            if self.value[i] >= 255:
                self.value[i] = 0
                continue
            else:
                self.value[i] += 1
                break


cdef class _BaseMode(AESBase):

    def __cinit__(self, key, *args, **kwargs):
        """Internal class. Please do not use."""
        self.n_rounds = {16: 10, 192: 12, 32: 14}[len(key)]
        if self.n_rounds is None:
            raise ValueError('invalid key size')
        self._keys = self._expand_key(key, self.n_rounds)


cdef class _EncryptorECB(_BaseMode):

    def __cinit__(self, key):
        super(_EncryptorECB, self).__init__(key)

    cpdef bytes update(self, bytes data):
        if len(data) % 16 != 0:
            raise ValueError('plaintext length must be a multiple of 16')

        out = b''
        cdef bytes block
        for block in self._iterate_blocks(data):
            out += self._encrypt_block(block)

        return out


cdef class _DecryptorECB(_BaseMode):

    def __cinit__(self, key):
        super(_DecryptorECB, self).__init__(key)

    cpdef bytes update(self, bytes data):
        if len(data) % 16 != 0:
            raise ValueError('ciphertext length must be a multiple of 16')

        out = b''
        for block in self._iterate_blocks(data):
            out += self._decrypt_block(block)

        return out


cdef class _EncryptorCBC(_BaseMode):
    cdef bytes _iv

    def __cinit__(self, key, iv):
        super(_EncryptorCBC, self).__init__(key)
        self._iv = iv

    cpdef bytes update(self, bytes data):
        if len(data) % 16 != 0:
            raise ValueError('plaintext length must be a multiple of 16')

        cdef bytes out, block
        out = b''
        for block in self._iterate_blocks(data):
            out += self._encrypt_block(self.xor_bytes(block, self._iv))
            self._iv = out[-16:]

        return out


cdef class _DecryptorCBC(_BaseMode):
    cdef bytes _iv

    def __cinit__(self, key, iv):
        super(_DecryptorCBC, self).__init__(key)
        self._iv = iv

    cpdef bytes update(self, bytes data):
        if len(data) % 16 != 0:
            raise ValueError('plaintext length must be a multiple of 16')

        cdef bytes out, block
        out = b''
        for block in self._iterate_blocks(data):
            out += self.xor_bytes(self._iv, self._decrypt_block(block))
            self._iv = block

        return out


cdef class _EncryptorCTR(_BaseMode):
    cdef bytearray _keystream
    cdef _Counter _counter

    def __cinit__(self, key, nonce):
        super(_EncryptorCTR, self).__init__(key)
        self._counter = _Counter(nonce)
        self._keystream = bytearray()

    cpdef bytes update(self, bytes data):
        while len(self._keystream) < len(data):
            self._keystream += self._encrypt_block(self._counter.value)
            self._counter.inc()
        cdef bytes out
        out = self.xor_bytes(self._keystream[:len(data)], data)
        self._keystream = self._keystream[len(data):]
        return out


cdef class _DecryptorCTR(_EncryptorCTR):
    pass


cdef class _EncryptorOFB(_BaseMode):
    cdef bytes _iv
    cdef bytearray _keysteam

    def __cinit__(self, key, iv):
        super(_EncryptorOFB, self).__init__(key)
        self._iv = iv

    cpdef bytes update(self, data):
        while len(self._keystream) < len(data):
            self._iv = self._encrypt_block(self._iv)
            self._keystream += self._iv

        out = self.xor_bytes(self._keystream[:len(data)], data)
        self._keystream = self._keystream[:len(data)]
        return out


cdef class _DecryptorOFB(_EncryptorOFB):
    pass


cdef class _EncryptorCFB(_BaseMode):
    cdef bytes _iv

    def __cinit__(self, key, iv):
        super(_EncryptorCFB, self).__init__(key)
        self._iv = iv

    cpdef bytes update(self, data):
        out = b''
        for block in self._iterate_blocks(data):
            self._iv = self.xor_bytes(block, self._encrypt_block(self._iv))
            out += self._iv
        missing_data = len(data) % 16
        if missing_data != 0:
            temp_iv = self.xor_bytes(data[-missing_data:], self._encrypt_block(self._iv)[:missing_data])
            self._iv = self._iv[-(16 - missing_data):] + temp_iv
            out += temp_iv

        return out


cdef class _DecryptorCFB(_BaseMode):
    cdef bytes _iv

    def __cinit__(self, key, iv):
        super(_DecryptorCFB, self).__init__(key)
        self._iv = iv

    cpdef bytes update(self, data):
        out = b''
        for block in self._iterate_blocks(data):
            out += self.xor_bytes(block, self._encrypt_block(self._iv))
            self._iv = block
        missing_data = len(data) % 16
        if missing_data != 0:
            temp_iv = self.xor_bytes(data[-missing_data:], self._encrypt_block(self._iv)[:missing_data])
            self._iv = self._iv[-(16 - missing_data):] + temp_iv
            out += temp_iv
        return out
