#!/usr/bin/env python3
## \file uint64.py
#  \brief Unsigned 64-bit Integer
import struct

class uint64:

    def __init__(self, integer, little=False):
        self.little = little
        if little:
            self._endian = '<'
        else:
            self._endian = '>'
        self.integer = integer

    def __bytes__(self):
        return struct.pack("%sQ" % self._endian, int(self.integer))

    def __str__(self):
        return "%d" % self.integer

    def __len__(self):
        return len(bytes(self))

    def from_bytes(b, little=False):
        if little:
            _endian = '<'
        else:
            _endian = '>'
        integer, = struct.unpack("%sQ" % _endian, b[:8])
        return uint64(integer), b[8:]
