#!/usr/bin/env python3
## \file elfsect.py
#  \brief Classes for ELF section interpretation
from makeelf.type.enum import Enum
from makeelf.type.align import align,unalign
from makeelf.type.uint32 import uint32

## \class DT
#  \brief Dynamic Array Tags
class DT(Enum):
    """d_tag enumeration"""
    DT_NULL = 0
    DT_NEEDED = 1
    DT_PLTRELSZ = 2
    DT_PLTGOT = 3
    DT_HASH = 4
    DT_STRTAB = 5
    DT_SYMTAB = 6
    DT_RELA = 7
    DT_RELASZ = 8
    DT_RELAENT = 9
    DT_STRSZ = 10
    DT_SYMENT = 11
    DT_INIT = 12
    DT_FINI = 13
    DT_SONAME = 14
    DT_RPATH = 15
    DT_SYMBOLIC = 16
    DT_REL = 17
    DT_RELSZ = 18
    DT_RELENT = 19
    DT_PLTREL = 20
    DT_DEBUG = 21
    DT_TEXTREL = 22
    DT_JMPREL = 23
    DT_BIND_NOW = 24
    DT_INIT_ARRAY = 25
    DT_FINI_ARRAY = 26
    DT_INIT_ARRAYSZ = 27
    DT_FINI_ARRAYSZ = 28
    DT_RUNPATH = 29
    DT_FLAGS = 30

    # This is used to mark a range of dynamic tags.  It is not really
    # a tag value.
    DT_ENCODING = 32

    DT_PREINIT_ARRAY = 32
    DT_PREINIT_ARRAYSZ = 33
    DT_LOOS = 0x6000000d
    DT_HIOS = 0x6ffff000
    DT_LOPROC = 0x70000000
    DT_HIPROC = 0x7fffffff


## \class Elf32_Dyn
#  \brief .dynamic section
class Elf32_Dyn:

    def __init__(self, d_tag=DT.DT_NULL, d_val=None, d_ptr=None, little=False):
        if isinstance(d_tag, DT):
            ## Value of type \link DT \endlink
            #  \details Controls if d_val or d_ptr is present
            self.d_tag = d_tag
        elif d_tag in map(int, DT):
            self.d_tag = DT(d_tag)
        elif isinstance(d_tag, int):
            # TODO: log warning message
            self.d_tag = uint32(d_tag, little)
        else:
            self.d_tag = DT[d_tag]

        # TODO: set only one of d_val or d_ptr

        ## Integer of various interpretations
        self.d_val = d_val

        ## Program virtual addresses
        self.d_ptr = d_ptr

        ## Header endianness indicator
        #  \details Is true, if header values are meant to be stored as
        #  little-endian or false otherwise
        self.little = little # should not be used, but for consistency set it

    def __str__(self):
        # TODO: print d_val/d_ptr conditionally
        return '{d_tag=%s, d_val=%s, d_ptr=%s}' % (self.d_tag, self.d_val,
                self.d_ptr)

    def __repr__(self):
        return '%s(%s, %s, %s)' % (type(self).__name__,
                self.d_tag, repr(self.d_val), repr(self.d_ptr))

    def __bytes__(self):
        d_tag = bytes(self.d_tag)
        d_val = uint32(self.d_val, little=self.little)
        d_ptr = uint32(self.d_ptr, little=self.little)

        # make sure d_tag is enum, before reversing bytes
        # other way it may be already reversed
        if self.little and isinstance(self.d_tag, DT):
            d_tag = bytes(reversed(d_tag))

        return bytes(d_tag) + bytes(d_val)

    def from_bytes(b, little=False):
        d_tag, b = uint32.from_bytes(b, little)
        d_val, b = uint32.from_bytes(b, little)
        d_ptr = d_val
        return Elf32_Dyn(d_tag.integer, d_val.integer, d_ptr.integer), b

    def __len__(self):
        return len(bytes(self))
