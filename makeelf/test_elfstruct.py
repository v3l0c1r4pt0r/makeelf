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


class Elf32_EhdrTests(unittest.TestCase):

    tv_endianness = [True, False, True, False, True]

    tv_bytes = [
            b'\x7fELF\1\2\1\0\0\0\0\0\0\0\0\0' + b'\1\0\0\0\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x34\0\0\0\0\0\0\0\0\0\0\0',
            b'\x7fELF\1\2\1\0\0\0\0\0\0\0\0\0' + b'\0\1\0\0\0\0\0\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x34\0\0\0\0\0\0\0\0\0\0',
            b'\x7fELF\1\1\1\0\0\0\0\0\0\0\0\0' + b'\0\0\0\0\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x34\0\0\0\0\0\0\0\0\0\0\0',
            b'\x7fELF\1\2\1\0\0\0\0\0\0\0\0\0' + b'\0\0\0\0\0\0\0\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x34\0\0\0\0\0\0\0\0\0\0',
            b'\x7fELF\0\1\0\1\0\0\0\0\0\0\0\0' + b'\2\0\3\0\2\0\0\0\1\0\0\0\2\0\0\0\3\0\0\0\0\0\0\0\x34\0\4\0\5\0\6\0\7\0\x08\0',
           ]

    tv_obj = [
            Elf32_Ehdr(little=True),
            Elf32_Ehdr(),
            Elf32_Ehdr(e_ident=Elf32_e_ident(EI_CLASS=ELFCLASS.ELFCLASS32,
                EI_DATA=ELFDATA.ELFDATA2LSB, EI_VERSION=EV.EV_CURRENT,
                EI_OSABI=ELFOSABI.ELFOSABI_NONE, little=True),
                e_type=ET.ET_NONE, e_machine=EM.EM_NONE, e_version=1, e_entry=0, e_phoff=0, e_shoff=0, e_flags=0, e_ehsize=52, e_phentsize=0, e_phnum=0, e_shentsize=0, e_shnum=0, e_shstrndx=0, little=True),
            Elf32_Ehdr(e_ident=Elf32_e_ident(EI_CLASS=ELFCLASS.ELFCLASS32,
                EI_DATA=ELFDATA.ELFDATA2MSB, EI_VERSION=EV.EV_CURRENT,
                EI_OSABI=ELFOSABI.ELFOSABI_NONE),
                e_type=ET.ET_NONE, e_machine=EM.EM_NONE, e_version=1, e_entry=0, e_phoff=0, e_shoff=0, e_flags=0, e_ehsize=52, e_phentsize=0, e_phnum=0, e_shentsize=0, e_shnum=0, e_shstrndx=0),
            Elf32_Ehdr(e_ident=Elf32_e_ident(EI_CLASS=ELFCLASS.ELFCLASSNONE,
                EI_DATA=ELFDATA.ELFDATA2LSB, EI_VERSION=EV.EV_NONE,
                EI_OSABI=ELFOSABI.ELFOSABI_HPUX, little=True),
                e_type=ET.ET_EXEC, e_machine=EM.EM_386, e_version=2, e_entry=1, e_phoff=2, e_shoff=3, e_flags=0, e_ehsize=52, e_phentsize=4, e_phnum=5, e_shentsize=6, e_shnum=7, e_shstrndx=8, little=True)
            ]

    tv_str = [
            '{e_ident={EI_MAG=\'^?ELF\', EI_CLASS=ELFCLASS.ELFCLASS32, EI_DATA=ELFDATA.ELFDATA2MSB, EI_VERSION=EV.EV_CURRENT, EI_OSABI=ELFOSABI.ELFOSABI_NONE}, e_type=ET.ET_REL, e_machine=EM.EM_NONE, e_version=1, e_entry=0, e_phoff=0, e_shoff=0, e_flags=0, e_ehsize=52, e_phentsize=0, e_phnum=0, e_shentsize=0, e_shnum=0, e_shstrndx=0}',
            '{e_ident={EI_MAG=\'^?ELF\', EI_CLASS=ELFCLASS.ELFCLASS32, EI_DATA=ELFDATA.ELFDATA2MSB, EI_VERSION=EV.EV_CURRENT, EI_OSABI=ELFOSABI.ELFOSABI_NONE}, e_type=ET.ET_REL, e_machine=EM.EM_NONE, e_version=1, e_entry=0, e_phoff=0, e_shoff=0, e_flags=0, e_ehsize=52, e_phentsize=0, e_phnum=0, e_shentsize=0, e_shnum=0, e_shstrndx=0}',
            '{e_ident={EI_MAG=\'^?ELF\', EI_CLASS=ELFCLASS.ELFCLASS32, EI_DATA=ELFDATA.ELFDATA2LSB, EI_VERSION=EV.EV_CURRENT, EI_OSABI=ELFOSABI.ELFOSABI_NONE}, e_type=ET.ET_NONE, e_machine=EM.EM_NONE, e_version=1, e_entry=0, e_phoff=0, e_shoff=0, e_flags=0, e_ehsize=52, e_phentsize=0, e_phnum=0, e_shentsize=0, e_shnum=0, e_shstrndx=0}',
            '{e_ident={EI_MAG=\'^?ELF\', EI_CLASS=ELFCLASS.ELFCLASS32, EI_DATA=ELFDATA.ELFDATA2MSB, EI_VERSION=EV.EV_CURRENT, EI_OSABI=ELFOSABI.ELFOSABI_NONE}, e_type=ET.ET_NONE, e_machine=EM.EM_NONE, e_version=1, e_entry=0, e_phoff=0, e_shoff=0, e_flags=0, e_ehsize=52, e_phentsize=0, e_phnum=0, e_shentsize=0, e_shnum=0, e_shstrndx=0}',
            '{e_ident={EI_MAG=\'^?ELF\', EI_CLASS=ELFCLASS.ELFCLASSNONE, EI_DATA=ELFDATA.ELFDATA2LSB, EI_VERSION=EV.EV_NONE, EI_OSABI=ELFOSABI.ELFOSABI_HPUX}, e_type=ET.ET_EXEC, e_machine=EM.EM_386, e_version=2, e_entry=1, e_phoff=2, e_shoff=3, e_flags=0, e_ehsize=52, e_phentsize=4, e_phnum=5, e_shentsize=6, e_shnum=7, e_shstrndx=8}',
            ]

    tv_repr = [
            'Elf32_Ehdr(Elf32_e_ident(b\'\\x7fELF\', ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2MSB, EV.EV_CURRENT, ELFOSABI.ELFOSABI_NONE), ET.ET_REL, EM.EM_NONE, 1, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0)',
            'Elf32_Ehdr(Elf32_e_ident(b\'\\x7fELF\', ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2MSB, EV.EV_CURRENT, ELFOSABI.ELFOSABI_NONE), ET.ET_REL, EM.EM_NONE, 1, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0)',
            'Elf32_Ehdr(Elf32_e_ident(b\'\\x7fELF\', ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2LSB, EV.EV_CURRENT, ELFOSABI.ELFOSABI_NONE), ET.ET_NONE, EM.EM_NONE, 1, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0)',
            'Elf32_Ehdr(Elf32_e_ident(b\'\\x7fELF\', ELFCLASS.ELFCLASS32, ELFDATA.ELFDATA2MSB, EV.EV_CURRENT, ELFOSABI.ELFOSABI_NONE), ET.ET_NONE, EM.EM_NONE, 1, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0)',
            'Elf32_Ehdr(Elf32_e_ident(b\'\\x7fELF\', ELFCLASS.ELFCLASSNONE, ELFDATA.ELFDATA2LSB, EV.EV_NONE, ELFOSABI.ELFOSABI_HPUX), ET.ET_EXEC, EM.EM_386, 2, 1, 2, 3, 0, 52, 4, 5, 6, 7, 8)',
            ]

    def test_str(self):
        for i in range(len(Elf32_EhdrTests.tv_obj)):
            tv_obj = Elf32_EhdrTests.tv_obj[i]
            tv_str = Elf32_EhdrTests.tv_str[i]

            invector = tv_obj
            expected = tv_str
            actual = str(invector)

            self.assertEqual(expected, actual, 'error at element {}'.format(i))

    def test_repr(self):
        for i in range(len(Elf32_EhdrTests.tv_obj)):
            tv_obj = Elf32_EhdrTests.tv_obj[i]
            tv_repr = Elf32_EhdrTests.tv_repr[i]

            invector = tv_obj
            expected = tv_repr
            actual = repr(invector)

            self.assertEqual(expected, actual, 'error at element {}'.format(i))

    def test_len(self):
        for i in range(len(Elf32_EhdrTests.tv_obj)):
            tv_obj = Elf32_EhdrTests.tv_obj[i]

            invector = tv_obj
            expected = 52
            actual = len(invector)

            self.assertEqual(expected, actual, 'error at element {}'.format(i))

    def test_bytes(self):
        for i in range(len(Elf32_EhdrTests.tv_bytes)):
            tv_bytes = Elf32_EhdrTests.tv_bytes[i]
            tv_obj = Elf32_EhdrTests.tv_obj[i]

            invector = tv_obj
            expected = tv_bytes
            actual = bytes(invector)

            self.assertEqual(expected, actual, 'error at element {}'.format(i))

    def test_from_bytes(self):
        for i in range(len(Elf32_EhdrTests.tv_bytes)):
            tv_bytes = Elf32_EhdrTests.tv_bytes[i]
            tv_obj = Elf32_EhdrTests.tv_obj[i]
            tv_endianness = Elf32_EhdrTests.tv_endianness[i]

            invector = tv_bytes + b'\x13\x37'
            expected = tv_obj, b'\x13\x37'
            actual = Elf32_Ehdr.from_bytes(invector, tv_endianness)

            #self.assertEqual(expected[0].little, actual[0].little, i)
            self.assertEqual(expected, actual, 'error at element {}'.format(i))
