# ----------------------------------------------------------------------------- #
# Copyright (c) 2020 Legorooj <legorooj@pm.me>. This file is licensed under the #
# MIT license. See the LICENSE file in the root of this repository for details. #
# ----------------------------------------------------------------------------- #
# cython: language_level=3

cpdef list _expand_key(bytes master_key, int rounds)
cpdef bytes xor_bytes(a, b)

cdef class AESBase:
    cdef public int n_rounds
    cdef public list _keys
    cpdef bytes _decrypt_block(self, bytes block)
    cpdef bytes _encrypt_block(self, bytes block)
