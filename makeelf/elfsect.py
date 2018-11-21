#!/usr/bin/env python3
## \file elfsect.py
#  \brief Classes for ELF section interpretation
import unittest
from makeelf.type.enum import Enum
from makeelf.type.align import align,unalign
from makeelf.type.uint32 import uint32
from makeelf.elfstruct import SHN

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
        return Elf32_Dyn(d_tag.integer, d_val.integer, d_ptr.integer, little), b

    def __len__(self):
        return len(bytes(self))


class Elf32_DynTests(unittest.TestCase):

    tv_endianness = [True, False]

    tv_bytes = [b' \0\0\0\1\2\3\4', b'\0\0\0 \4\3\2\1']

    tv_obj = [\
            Elf32_Dyn(DT.DT_ENCODING, 0x04030201, little=True),
            Elf32_Dyn(DT.DT_ENCODING, 0x04030201)]

    def test_str(self):
        for i in range(len(Elf32_DynTests.tv_bytes)):
            tv_bytes = Elf32_DynTests.tv_bytes[i]
            tv_obj = Elf32_DynTests.tv_obj[i]

            invector = tv_obj
            expected = '{d_tag=DT.DT_ENCODING, d_val=67305985, d_ptr=None}'
            actual = str(invector)

            self.assertEqual(expected, actual)

    def test_repr(self):
        for i in range(len(Elf32_DynTests.tv_bytes)):
            tv_bytes = Elf32_DynTests.tv_bytes[i]
            tv_obj = Elf32_DynTests.tv_obj[i]

            invector = tv_obj
            expected = 'Elf32_Dyn(DT.DT_ENCODING, 67305985, None)'
            actual = repr(invector)

            self.assertEqual(expected, actual)

    def test_len(self):
        for i in range(len(Elf32_DynTests.tv_bytes)):
            tv_bytes = Elf32_DynTests.tv_bytes[i]
            tv_obj = Elf32_DynTests.tv_obj[i]

            invector = tv_obj
            expected = 8
            actual = len(invector)

            self.assertEqual(expected, actual)

    def test_bytes(self):
        for i in range(len(Elf32_DynTests.tv_bytes)):
            tv_bytes = Elf32_DynTests.tv_bytes[i]
            tv_obj = Elf32_DynTests.tv_obj[i]

            invector = tv_obj
            expected = tv_bytes
            actual = bytes(invector)

            self.assertEqual(expected, actual)

    @unittest.skip('d_val and d_ptr should be selectively hidden - it is not')
    def test_from_bytes(self):
        for i in range(len(Elf32_DynTests.tv_bytes)):
            tv_bytes = Elf32_DynTests.tv_bytes[i]
            tv_obj = Elf32_DynTests.tv_obj[i]
            tv_endianness = Elf32_DynTests.tv_endianness[i]

        invector = tv_bytes + b'\x13\x37'
        expected = tv_obj, b'\x13\x37'
        actual = Elf32_Dyn.from_bytes(invector, tv_endianness)

        self.assertEqual(expected, actual)


## \class STB
#  \brief Symbol Table Binding
class STB(Enum):
    STB_LOCAL = 0
    STB_GLOBAL = 1
    STB_WEAK = 2
    STB_LOOS = 10
    STB_HIOS = 12
    STB_LOPROC = 13
    STB_HIPROC = 15


## \class STT
#  \brief Symbol Types
class STT(Enum):
    STT_NOTYPE = 0
    STT_OBJECT = 1
    STT_FUNC = 2
    STT_SECTION = 3
    STT_FILE = 4
    STT_COMMON = 5
    STT_TLS = 6
    STT_LOOS = 10
    STT_HIOS = 12
    STT_LOPROC = 13
    STT_HIPROC = 15


## \class STV
#  \brief Symbol Visibility
class STV(Enum):
    STV_DEFAULT = 0
    STV_INTERNAL = 1
    STV_HIDDEN = 2
    STV_PROTECTED = 3


## \class Elf32_Sym
#  \brief Symbol Table Entry
class Elf32_Sym:

    def __init__(self, st_name=0, st_value=0, st_size=0, st_info=0, st_other=0,
            st_shndx=SHN.SHN_UNDEF, little=False):
        ## Symbol name in .strtab
        self.st_name = st_name
        ## Symbol value
        self.st_value = st_value
        ## Size of the symbol
        self.st_size = st_size
        ## Packed values of \link STB \endlink and \link STT \endlink
        self.st_info = st_info
        ## Packed values of \link STV \endlink
        self.st_other = st_other
        ## Index of section, symbol is based on
        self.st_shndx = st_shndx

        ## Header endianness indicator
        #  \details Is true, if header values are meant to be stored as
        #  little-endian or false otherwise
        self.little = little

    def __str__(self):
        return '{st_name=%s, st_value=%s, st_size=%s, st_info=%s, ' \
                'st_other=%s, st_shndx=%s}' % (self.st_name, self.st_value,
                        self.st_size, self.st_info, self.st_other,
                        self.st_shndx)

    def __repr__(self):
        return '%s(%s, %s, %s, %s, %s, %s)' % (type(self).__name__,
                self.st_name, self.st_value, self.st_size, self.st_info,
                self.st_other, self.st_shndx)

    def __bytes__(self):
        st_name = uint32(self.st_name, little=self.little)
        st_value = uint32(self.st_value, little=self.little)
        st_size = uint32(self.st_size, little=self.little)
        st_info = uint8(self.st_info, little=self.little)
        st_other = uint8(self.st_other, little=self.little)
        st_shndx = uint16(self.st_shndx, little=self.little)

        return bytes(st_name) + bytes(st_value) + bytes(st_size) + \
                bytes(st_info) + bytes(st_other) + bytes(st_shndx)

    def from_bytes(b, little=False):
        st_name, b = uint32.from_bytes(b, little=little)
        st_value, b = uint32.from_bytes(b, little=little)
        st_size, b = uint32.from_bytes(b, little=little)
        st_info, b = uint8.from_bytes(b, little=little)
        st_other, b = uint8.from_bytes(b, little=little)
        st_shndx, b = uint16.from_bytes(b, little=little)

        return Elf32_Sym(st_name.integer, st_value.integer, st_size.integer,
                st_info.integer, st_other.integer, st_shndx.integer), b

    def __len__(self):
        return len(bytes(self))


if __name__ == '__main__':
    # TODO: make some real tests
    print('tests')
    print('Elf32_Dyn as section')
    from makeelf.elf import *
    e,b = ELF.from_file('libimp.so')
    expected = bytes(e.Elf)
    h,b = e.get_section_by_name('.dynamic')
    print('.dynamic', h)
    dynamic = []
    while len(b) > 0:
        dyn, b = Elf32_Dyn.from_bytes(b, e.little)
        dynamic.append(dyn)
    e.Elf.sections[e.Elf.Shdr_table.index(h)] = dynamic
    b = bytes(e.Elf)
    actual = b
    print('serialized')
    fd = os.open('libimp.tmp.so', os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    os.write(fd, b)
    os.close(fd)
    print('written')
    for i in range(len(dynamic)):
        expdyn = e.get_section_by_name('.dynamic')[1][i]
        actdyn = dynamic[i]
        if expdyn != actdyn:
            raise Exception(str(expdyn) + '\n' + str(actdyn))
    print('dyns deserialized correctly')
    for i, byte in enumerate(actual):
        if byte != expected[i]:
            raise Exception('objects differ at offset {} (expected {}, got {})'.format(hex(i),hex(byte),hex(expected[i])))
    print('OK')
