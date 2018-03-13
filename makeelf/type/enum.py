#!/usr/bin/env python3
## \file enum.py
#  \brief enumeration type
import struct
import sys
from enum import IntEnum
from makeelf.type.align import align

"""Serializable enum object

Always serializes/deserializes to/from big endian integers"""
class Enum(IntEnum):

    def _field_width(floor, ceiling):
        diff = ceiling - floor
        r = diff
        i = 1
        while r // 256 != 0:
            i += 1
            r = r // 256
            m = r % 256
        return i

    @classmethod
    def _max_value(cls):
        return max(map(int,cls))

    """Converts int into bytes array of arbitrary length and in big order"""
    def _value_as_bytes(field):
        ret = []
        r = field
        i = 1
        m = 0
        while r // 256 != 0:
            i += 1
            m = r % 256
            r = r // 256
            ret.append(m)
        ret.append(r)
        return bytes(ret)

    """Converts bytes array of arbitrary length and in little order into int"""
    def _bytes_as_value(b):
        value = 0
        for i, v in enumerate(b):
            value += 256**i * v
        return value

    def __bytes__(self):
        max_val = type(self)._max_value()
        field_width = Enum._field_width(0, max_val)
        b = Enum._value_as_bytes(int(self))
        # if last set byte is less than width of the field, align
        b = align(b, field_width)
        if sys.byteorder == 'little':
            b = bytes(reversed(b))
        return b

    @classmethod
    def from_bytes(cls, b, little=False):
        max_val = cls._max_value()
        fw = Enum._field_width(0, max_val)
        this, b = (b[:fw], b[fw:])
        if sys.byteorder == 'little':
            this = bytes(reversed(this))
        # in case of deserialization we need to get endianness from caller as
        # only we know how many bytes we should reverse to get proper enum value
        if little:
            this = bytes(reversed(this))
        return cls(cls._bytes_as_value(this)), b
