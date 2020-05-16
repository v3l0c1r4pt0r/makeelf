#!/usr/bin/env python3
import unittest
from makeelf.elfsect import *

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

            self.assertEqual(expected, actual, 'error at element {}'.format(i))

    def test_repr(self):
        for i in range(len(Elf32_DynTests.tv_bytes)):
            tv_bytes = Elf32_DynTests.tv_bytes[i]
            tv_obj = Elf32_DynTests.tv_obj[i]

            invector = tv_obj
            expected = 'Elf32_Dyn(DT.DT_ENCODING, 67305985, None)'
            actual = repr(invector)

            self.assertEqual(expected, actual, 'error at element {}'.format(i))

    def test_len(self):
        for i in range(len(Elf32_DynTests.tv_bytes)):
            tv_bytes = Elf32_DynTests.tv_bytes[i]
            tv_obj = Elf32_DynTests.tv_obj[i]

            invector = tv_obj
            expected = 8
            actual = len(invector)

            self.assertEqual(expected, actual, 'error at element {}'.format(i))

    def test_bytes(self):
        for i in range(len(Elf32_DynTests.tv_bytes)):
            tv_bytes = Elf32_DynTests.tv_bytes[i]
            tv_obj = Elf32_DynTests.tv_obj[i]

            invector = tv_obj
            expected = tv_bytes
            actual = bytes(invector)

            self.assertEqual(expected, actual, 'error at element {}'.format(i))

    @unittest.skip('d_val and d_ptr should be selectively hidden - it is not')
    def test_from_bytes(self):
        for i in range(len(Elf32_DynTests.tv_bytes)):
            tv_bytes = Elf32_DynTests.tv_bytes[i]
            tv_obj = Elf32_DynTests.tv_obj[i]
            tv_endianness = Elf32_DynTests.tv_endianness[i]

        invector = tv_bytes + b'\x13\x37'
        expected = tv_obj, b'\x13\x37'
        actual = Elf32_Dyn.from_bytes(invector, tv_endianness)

        self.assertEqual(expected, actual, 'error at element {}'.format(i))


class Elf32_SymTests(unittest.TestCase):

    st_info = (int(STB.STB_WEAK) << 4) + int(STT.STT_OBJECT)
    st_other = int(STV.STV_PROTECTED)

    tv_endianness = [True, False]

    tv_bytes = [b'\3\2\1\0\xde\xc0\xdd\xba\xff\xee\xdd\xcc\x21\3\x12\0',
            b'\0\1\2\3\xba\xdd\xc0\xde\xcc\xdd\xee\xff\x21\3\0\x12']

    tv_obj = [\
            Elf32_Sym(0x010203, 0xbaddc0de, 0xccddeeff, st_info, st_other,
                0x12, little=True),
            Elf32_Sym(0x010203, 0xbaddc0de, 0xccddeeff, st_info, st_other,
                0x12)]

    def test_str(self):
        for i in range(len(Elf32_SymTests.tv_bytes)):
            tv_bytes = Elf32_SymTests.tv_bytes[i]
            tv_obj = Elf32_SymTests.tv_obj[i]

            invector = tv_obj
            expected = '{st_name=66051, st_value=3135095006, '\
                    'st_size=3437096703, st_info=33, st_other=3, st_shndx=18}'
            # TODO: should be st_info=STB.STB_WEAK+STT.STT_OBJECT,
            # st_other=STV.STV_PROTECTED
            actual = str(invector)

            self.assertEqual(expected, actual, 'error at element {}'.format(i))

    def test_repr(self):
        for i in range(len(Elf32_SymTests.tv_bytes)):
            tv_bytes = Elf32_SymTests.tv_bytes[i]
            tv_obj = Elf32_SymTests.tv_obj[i]

            invector = tv_obj
            expected = 'Elf32_Sym(66051, 3135095006, 3437096703, 33, 3, 18)'
            # TODO: st_info should be STB.STB_WEAK+STT.STT_OBJECT
            # TODO: st_other shoudl be STV.STV_PROTECTED
            actual = repr(invector)

            self.assertEqual(expected, actual, 'error at element {}'.format(i))

    def test_len(self):
        for i in range(len(Elf32_SymTests.tv_bytes)):
            tv_bytes = Elf32_SymTests.tv_bytes[i]
            tv_obj = Elf32_SymTests.tv_obj[i]

            invector = tv_obj
            expected = 16
            actual = len(invector)

            self.assertEqual(expected, actual, 'error at element {}'.format(i))

    def test_bytes(self):
        for i in range(len(Elf32_SymTests.tv_bytes)):
            tv_bytes = Elf32_SymTests.tv_bytes[i]
            tv_obj = Elf32_SymTests.tv_obj[i]

            invector = tv_obj
            expected = tv_bytes
            actual = bytes(invector)

            self.assertEqual(expected, actual, 'error at element {}'.format(i))

    def test_from_bytes(self):
        for i in range(len(Elf32_SymTests.tv_bytes)):
            tv_bytes = Elf32_SymTests.tv_bytes[i]
            tv_obj = Elf32_SymTests.tv_obj[i]
            tv_endianness = Elf32_SymTests.tv_endianness[i]

            invector = tv_bytes + b'\x13\x37'
            expected = tv_obj, b'\x13\x37'
            actual = Elf32_Sym.from_bytes(invector, tv_endianness)

            #self.assertEqual(expected[0].little, actual[0].little, i)
            self.assertEqual(expected, actual, 'error at element {}'.format(i))
