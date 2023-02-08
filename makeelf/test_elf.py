#!/usr/bin/env python3
import unittest
from makeelf.elf import *

class ELFTests(unittest.TestCase):

    tv_bytes_l = b' \0\0\0\1\2\3\4\0\0\0\5\x37\x13\0\0'

    tv_bytes_b = b' \0\0\0\4\3\2\1\5\0\0\0\0\0\x13\x37'

    tv_obj_l = [\
            Elf32_Dyn(DT.DT_ENCODING, 0x04030201, little=True),
            Elf32_Dyn(DT.DT_STRTAB, 0x1337, little=True)]

    tv_obj_b = [\
            Elf32_Dyn(DT.DT_ENCODING, 0x04030201),
            Elf32_Dyn(DT.DT_STRTAB, 0x1337)]

    tv_elf_l = \
    b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
    + b'\x02\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x004\x00\x00\x00T\x00\x00\x00\x00\x00\x00\x004\x00 \x00\x01\x00(\x00\x03\x00\x01\x00'\
    + b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x01\x00\x00\x00'\
    + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xcc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xcc\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x007\x13\x00\x00\xe0\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'\
    + b'\0' + b'.shstrtab\0' + b'.dynamic\0' + tv_bytes_l

    tv_elf_b = \
    b'\x7fELF\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
    + b'\x00\x02\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x004\x00\x00\x00T\x00\x00\x00\x00\x004\x00 \x00\x01\x00(\x00\x03\x00\x01\x00'\
    + b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x01\x00\x00\x00'\
    + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xcc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xcc\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x007\x13\x00\x00\xe0\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'\
    + b'\0' + b'.shstrtab\0' + b'.dynamic\0' + tv_bytes_b

    def test_sections_l(self):
        tv_bytes = ELFTests.tv_bytes_l
        tv_elf = ELFTests.tv_elf_l

        invector = ELF(e_data=ELFDATA.ELFDATA2LSB)
        invector.append_section('.dynamic', tv_bytes, 0x1337)

        expected = tv_elf
        actual = bytes(invector)

        self.assertEqual(expected, actual)

    @unittest.skip('test vector not ready yet')
    def test_sections_b(self):
        tv_bytes = ELFTests.tv_bytes_b
        tv_elf = ELFTests.tv_elf_b

        invector = ELF(e_data=ELFDATA.ELFDATA2MSB)
        invector.append_section('.dynamic', tv_bytes, 0x1337)

        expected = tv_elf
        actual = bytes(invector)

        h,a = invector.get_section_by_name('.dynamic')
        self.assertEqual(expected, actual)

    def test_phdr(self):
        data = b"TESTTEST"
        elf = ELF()
        section = elf.append_section("test", data, 0x12345678)
        phdr = elf._append_segment(PT.PT_LOAD, 0xDEADBEEF, 0xC0FFEE, len(data), len(data), PF.PF_R, [section])
        actual = bytes(elf)

        self.assertEqual(elf.Elf.Phdr_table[phdr].p_offset, elf.Elf.Shdr_table[section].sh_offset)

        expected = bytes.fromhex("""
            7f454c4601020100000000000000000000020000000000010000000000000034000000740000000000340020000200280003
            0001000000010000000000000000000000000000000000000000000000050000000100000001000000fcdeadbeef00c0ffee
            0000000800000008000000040000000100000000000000000000000000000000000000ec0000000000000000000000000000
            00000000000000000001000000030000000000000000000000ec00000010000000000000000000000001000000000000000b
            000000010000000012345678000000fc0000000800000000000000000000000100000000002e736873747274616200746573
            74005445535454455354
        """)
        self.assertEqual(expected, actual)
