#!/usr/bin/env python3
## \file uint8.py
#  \brief Unsigned 8-bit Integer
import struct

class uint8:

    def __init__(self, integer, little=False):
        self.little = little
        if little:
            self._endian = '<'
        else:
            self._endian = '>'
        self.integer = integer

    def __bytes__(self):
        return struct.pack("%sB" % self._endian, int(self.integer))[-1:]

    def __str__(self):
        return "%d" % self.integer

    def __len__(self):
        return len(bytes(self))

    def from_bytes(b, little=False):
        if little:
            _endian = '<'
        else:
            _endian = '>'
        integer, = struct.unpack("%sB" % _endian,b[:1])
        return uint8(integer), b[1:]
