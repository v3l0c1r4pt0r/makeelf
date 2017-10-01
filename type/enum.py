#!/usr/bin/env python3
# enumeration type
import struct
import sys
from enum import IntEnum

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

    def _field_as_bytes(field):
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

    def __bytes__(self):
        max_val = max(map(int,type(self)))
        field_width = Enum._field_width(0, max_val)
        b = Enum._field_as_bytes(int(self))
        if sys.byteorder == 'little':
            b = reversed(b)
        return bytes(b)
