#!/usr/bin/env python3
import unittest
from makeelf.elfstruct import *

class Elf32_e_identTests(unittest.TestCase):

    tv_endianness = [True, False, True, False, True]

    tv_bytes = [b'\x7fELF\1\2\1\0\0\0\0\0\0\0\0\0',
            b'\x7fELF\1\2\1\0\0\0\0\0\0\0\0\0',
            b'\x7fELF\1\1\1\0\0\0\0\0\0\0\0\0',
            b'\x7fELF\1\2\1\0\0\0\0\0\0\0\0\0',
            b'\x7fELF\0\1\1\1\0\0\0\0\0\0\0\0']

    tv_obj = [\
            Elf32_e_ident(little=True),
            Elf32_e_ident(),
            Elf32_e_ident(EI_CLASS=ELFCLASS.ELFCLASS32,
                EI_DATA=ELFDATA.ELFDATA2LSB, EI_VERSION=EV.EV_CURRENT,
                EI_OSABI=ELFOSABI.ELFOSABI_NONE, little=True),
            Elf32_e_ident(EI_CLASS=ELFCLASS.ELFCLASS32,
                EI_DATA=ELFDATA.ELFDATA2MSB, EI_VERSION=EV.EV_CURRENT,
                EI_OSABI=ELFOSABI.ELFOSABI_NONE),
            Elf32_e_ident(EI_CLASS=ELFCLASS.ELFCLASSNONE,
                EI_DATA=ELFDATA.ELFDATA2LSB, EI_VERSION=EV.EV_CURRENT,
                EI_OSABI=ELFOSABI.ELFOSABI_HPUX, little=True)]

    tv_str = ['{EI_MAG=\'^?ELF\', EI_CLASS=ELFCLASS.ELFCLASS32, EI_DATA=ELFDATA.ELFDATA2MSB, EI_VERSION=EV.EV_CURRENT, EI_OSABI=ELFOSABI.ELFOSABI_NONE}',
            '{EI_MAG=\'^?ELF\', EI_CLASS=ELFCLASS.ELFCLASS32, EI_DATA=ELFDATA.ELFDATA2MSB, EI_VERSION=EV.EV_CURRENT, EI_OSABI=ELFOSABI.ELFOSABI_NONE}',
            '{EI_MAG=\'^?ELF\', EI_CLASS=ELFCLASS.ELFCLASS32, EI_DATA=ELFDATA.ELFDATA2LSB, EI_VERSION=EV.EV_CURRENT, EI_OSABI=ELFOSABI.ELFOSABI_NONE}',
            '{EI_MAG=\'^?ELF\', EI_CLASS=ELFCLASS.ELFCLASS32, EI_DATA=ELFDATA.ELFDATA2MSB, EI_VERSION=EV.EV_CURRENT, EI_OSABI=ELFOSABI.ELFOSABI_NONE}',
            '{EI_MAG=\'^?ELF\', EI_CLASS=ELFCLASS.ELFCLASSNONE, EI_DATA=ELFDATA.ELFDATA2LSB, EI_VERSION=EV.EV_CURRENT, EI_OSABI=ELFOSABI.ELFOSABI_HPUX}']

    tv_repr = ['Elf32_e_ident(b\'\\x7fELF\', ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2MSB, EV.EV_CURRENT, ELFOSABI.ELFOSABI_NONE)',
            'Elf32_e_ident(b\'\\x7fELF\', ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2MSB, EV.EV_CURRENT, ELFOSABI.ELFOSABI_NONE)',
            'Elf32_e_ident(b\'\\x7fELF\', ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, EV.EV_CURRENT, ELFOSABI.ELFOSABI_NONE)',
            'Elf32_e_ident(b\'\\x7fELF\', ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2MSB, EV.EV_CURRENT, ELFOSABI.ELFOSABI_NONE)',
            'Elf32_e_ident(b\'\\x7fELF\', ELFCLASS.ELFCLASSNONE, ELFDATA.ELFDATA2LSB, EV.EV_CURRENT, ELFOSABI.ELFOSABI_HPUX)']

    def test_str(self):
        for i in range(len(Elf32_e_identTests.tv_obj)):
            tv_obj = Elf32_e_identTests.tv_obj[i]
            tv_str = Elf32_e_identTests.tv_str[i]

            invector = tv_obj
            expected = tv_str
            actual = str(invector)

            self.assertEqual(expected, actual, 'error at element {}'.format(i))

    def test_repr(self):
        for i in range(len(Elf32_e_identTests.tv_obj)):
            tv_obj = Elf32_e_identTests.tv_obj[i]
            tv_repr = Elf32_e_identTests.tv_repr[i]

            invector = tv_obj
            expected = tv_repr
            actual = repr(invector)

            self.assertEqual(expected, actual, 'error at element {}'.format(i))

    def test_len(self):
        for i in range(len(Elf32_e_identTests.tv_obj)):
            tv_obj = Elf32_e_identTests.tv_obj[i]

            invector = tv_obj
            expected = 16
            actual = len(invector)

            self.assertEqual(expected, actual, 'error at element {}'.format(i))

    def test_bytes(self):
        for i in range(len(Elf32_e_identTests.tv_bytes)):
            tv_bytes = Elf32_e_identTests.tv_bytes[i]
            tv_obj = Elf32_e_identTests.tv_obj[i]

            invector = tv_obj
            expected = tv_bytes
            actual = bytes(invector)

            self.assertEqual(expected, actual, 'error at element {}'.format(i))

    @unittest.skip('Comparison not implemented')
    def test_from_bytes(self):
        for i in range(len(Elf32_e_identTests.tv_bytes)):
            tv_bytes = Elf32_e_identTests.tv_bytes[i]
            tv_obj = Elf32_e_identTests.tv_obj[i]
            #tv_endianness = Elf32_e_identTests.tv_endianness[i]

            invector = tv_bytes + b'\x13\x37'
            expected = tv_obj, b'\x13\x37'
            actual = Elf32_e_ident.from_bytes(invector)

            #self.assertEqual(expected[0].little, actual[0].little, i)
            self.assertEqual(expected, actual, 'error at element {}'.format(i))
