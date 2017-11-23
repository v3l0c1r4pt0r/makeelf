#!/usr/bin/env python3
## \file utils.py
#  \brief Utility functions
def bytes_xor(lhs, rhs):
    res = []
    for a, b in zip(lhs, rhs):
        res.append(a ^ b)
    return bytes(res)
