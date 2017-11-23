#!/usr/bin/env python3
## \file uint24.py
#  \brief Unsigned 24-bit Integer
import struct

class uint24:

    def __init__(self, integer, little=False):
        self.little = little
        if little:
            self._endian = '<'
        else:
            self._endian = '>'
        self.integer = integer

    def __bytes__(self):
        return struct.pack("%sI" % self._endian, int(self.integer))[-3:]

    def __str__(self):
        return "%d" % self.integer

    def __len__(self):
        return len(bytes(self))

    def from_bytes(b, little=False):
        if little:
            _endian = '<'
        else:
            _endian = '>'
        integer, = struct.unpack("%sI" % _endian,b'\0'+b[:3])
        return uint24(integer), b[3:]
