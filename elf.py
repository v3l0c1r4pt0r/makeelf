#!/usr/bin/env python3
# module for high-level manipulation of ELF files
from elfstruct import *

class _Strtab:
    """Helper class for creating sections of type SHT_STRTAB

    Guards general rules and allows appending new strings"""

    def __init__(self):
        self.blob = b'\0'

    def __str__(self):
        return str(self.blob)

    def __repr__(self):
        return repr(self.blob)

    def __bytes__(self):
        return self.blob

    def __len__(self):
        return len(self.blob)

    def append(self, string):
        """Appends string to the end of section

        Returns offset of newly appended string"""

        # TODO: check if string does not contain any NULLs

        if isinstance(string, str):
            string = bytes(string, 'utf-8')

        ret = len(self.blob)
        self.blob += string + b'\0'
        return ret


class ELF:
    """This class is a wrapper on ELF structures provided by elfstruct module
    
    It provides set of functions allowing easy manipulation of ELF as a whole,
    without requirement of update of particular fields, especially offsets and
    section headers"""

    def __init__(self, e_class=ELFCLASS.ELFCLASS32, e_data=ELFDATA.ELFDATA2MSB,
            e_type=ET.ET_EXEC, e_machine=EM.EM_NONE):
        if e_class == ELFCLASS.ELFCLASS32:
            cls = Elf32
            hdr = Elf32_Ehdr
        else:
            raise Exception('ELF class %s currently unsupported' % e_class)

        if e_data == ELFDATA.ELFDATA2MSB:
            little = False
        elif e_data == ELFDATA.ELFDATA2LSB:
            little = True
        else:
            little = sys.byteorder == 'little'

        self.Elf = cls(Ehdr=hdr(e_ident=Elf32_e_ident(EI_CLASS=e_class, EI_DATA=e_data),
                e_type=e_type, e_machine=e_machine, little=little))

    def __str__(self):
        return str(self.Elf)

    def __repr__(self):
        return repr(self.Elf)

    def __bytes__(self):
        """Serialize ELF object into block of bytes

        Makes some header updates and serializes object to file, so output
        should always be valid ELF file"""
        cursor = len(self.Elf.Ehdr)

        # update offsets in Ehdr regarding Phdrs
        if len(self.Elf.Phdr_table) > 0:
            Phdr_len = 0
            for Phdr in self.Elf.Phdr_table:
                Phdr_len += len(Phdr)
            self.Elf.Ehdr.e_phoff = cursor
            self.Elf.Ehdr.e_phentsize = len(self.Elf.Phdr_table[0])
            self.Elf.Ehdr.e_phnum = len(self.Elf.Phdr_table)
            cursor += Phdr_len
        else:
            self.Elf.Ehdr.e_phoff = 0
            self.Elf.Ehdr.e_phentsize = 0
            self.Elf.Ehdr.e_phnum = 0

        # update offsets in Ehdr regarding Shdrs
        if len(self.Elf.Shdr_table) > 0:
            Shdr_len = 0
            for Shdr in self.Elf.Shdr_table:
                Shdr_len += len(Shdr)
            self.Elf.Ehdr.e_shoff = cursor
            self.Elf.Ehdr.e_shentsize = len(self.Elf.Shdr_table[0])
            self.Elf.Ehdr.e_shnum = len(self.Elf.Shdr_table)
            cursor += Shdr_len
        else:
            self.Elf.Ehdr.e_shoff = 0
            self.Elf.Ehdr.e_shentsize = 0
            self.Elf.Ehdr.e_shnum = 0

        # update section offsets in section headers
        for i, Shdr in enumerate(self.Elf.Shdr_table):
            section_len = len(self.Elf.sections[i])
            Shdr.sh_offset = cursor
            Shdr.sh_size = section_len
            cursor += section_len

        return bytes(self.Elf)

    def from_bytes(b):
        """Deserializes ELF from block of bytes"""
        return Elf32.from_bytes(b)

    def append_section(self, sec_name, sec_data, sec_addr):
        """Add new section to ELF file

        Name is automatically appended to .shstrtab section"""
        pass

    def append_special_section(self, sec_name, sec_data):
        """Add new special section to ELF file

        This function allows to add one of the special, structured sections to
        ELF file. Name is automatically appended to .shstrtab section"""
        pass
