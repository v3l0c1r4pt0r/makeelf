#!/usr/bin/env python3
## \file utils.py
#  \brief Utility functions

# Old code was quite slow on large files (e.g., several seconds on a 32MB ELF).
# Most of this was xor.  Large speedup from this SO answer:
#https://stackoverflow.com/questions/2119761/simple-python-challenge-fastest-bitwise-xor-on-data-buffers
#
# Although, this does add numpy as a dependency, so perhaps this should be checked at runtime?
from numpy import frombuffer, bitwise_xor, byte

def bytes_xor(lhs, rhs):
    a = frombuffer(lhs, dtype=byte)
    b = frombuffer(rhs, dtype=byte)
    c = bitwise_xor(a, b)
    r = c.tostring()
    return bytes(r)
