#!/usr/bin/env python3
## \file uint16.py
#  \brief Unsigned 16-bit Integer
import struct

class uint16:

    def __init__(self, integer, little=False):
        self.little = little
        if little:
            self._endian = '<'
        else:
            self._endian = '>'
        self.integer = integer

    def __bytes__(self):
        return struct.pack("%sH" % self._endian, int(self.integer))

    def __str__(self):
        return "%d" % self.integer

    def __len__(self):
        return len(bytes(self))

    def from_bytes(b, little=False):
        if little:
            _endian = '<'
        else:
            _endian = '>'
        integer, = struct.unpack("%sH" % _endian,b[:2])
        return uint16(integer), b[2:]
