#!/usr/bin/env python3
## \file elf.py
#  \brief Module for high-level manipulation of ELF files
from makeelf.elfstruct import *
import os

class _Strtab:
    """Helper class for creating sections of type SHT_STRTAB

    Guards general rules and allows appending new strings"""

    def __init__(self, b=None):
        if b is not None:
            self.blob = b
        else:
            self.blob = b'\0'

    def __str__(self):
        return str(self.blob)

    def __repr__(self):
        return repr(self.blob)

    def __bytes__(self):
        return self.blob

    def __len__(self):
        return len(self.blob)

    def __iadd__(lhs, rhs):
        if isinstance(rhs, str):
            rhs = bytes(rhs, 'utf-8')
        if rhs[-1:] == b'\0':
            lhs.blob += rhs
        else:
            lhs.blob += rhs + '\0'

    def append(self, string):
        """Appends string to the end of section

        Returns offset of newly appended string"""

        # TODO: check if string does not contain any NULLs

        if isinstance(string, str):
            string = bytes(string, 'utf-8')

        ret = len(self.blob)
        self.blob += string + b'\0'
        return ret

    def find(self, sub, start=None, end=None):
        if start is None:
            return self.blob.find(sub)
        elif end is None:
            return self.blob.find(sub, start)
        else:
            return self.blob.find(sub, start, end)


class _Symtab:
    """Helper class for handling symbol table"""

    def __init__(self, b=None):
        # init list
        self.lst = []

        # if bytes provided
        if b is not None:
            # convert b to list of Elf32_Sym
            while len(b) > 0:
                sym, b = Elf32_Sym.from_bytes(b)
                self.lst.append(sym)
        else:
            # create entry for index STN_UNDEF and append to table
            first = Elf32_Sym()
            self.lst.append(first)

    def __str__(self):
        return str(self.lst)

    def __repr__(self):
        return repr(self.lst)

    def __bytes__(self):
        b = b''
        for el in self.lst:
            b += bytes(el)
        return b

    def __len__(self):
        return len(bytes(self))

    def append(self, Symhdr):
        """Appends entry to symbol table

        Returns index of newly appended header"""
        if not isinstance(Symhdr, Elf32_Sym):
            # It is not expected, let's try converting throught bytes to struct
            Symhdr = Elf32_Sym.from_bytes(bytes(Symhdr))

        # store id of appended header
        ret = len(self.lst)

        self.lst.append(Symhdr)

        return ret


class ELF:
    """This class is a wrapper on ELF structures provided by elfstruct module
    
    It provides set of functions allowing easy manipulation of ELF as a whole,
    without requirement of update of particular fields, especially offsets and
    section headers"""

    def __init__(self, e_class=ELFCLASS.ELFCLASS32, e_data=ELFDATA.ELFDATA2MSB,
            e_type=ET.ET_EXEC, e_machine=EM.EM_NONE):
        if e_class is None and e_data is None and e_type is None and e_machine \
                is None:
            # create empty object
            return
        if e_class == ELFCLASS.ELFCLASS32:
            cls = Elf32
            hdr = Elf32_Ehdr
        else:
            raise Exception('ELF class %s currently unsupported' % e_class)

        if e_data == ELFDATA.ELFDATA2MSB:
            ## Header endianness indicator
            #  \details Is true, if header values are meant to be stored as
            #  little-endian or false otherwise
            self.little = False
        elif e_data == ELFDATA.ELFDATA2LSB:
            self.little = True
        else:
            self.little = sys.byteorder == 'little'

        ## Instance of \link elfstruct.Elf32 \endlink class
        #  \details Provides possibility to make any modification to ELF file,
        #  including setting fields to invalid values.
        self.Elf = cls(Ehdr=hdr(e_ident=Elf32_e_ident(EI_CLASS=e_class, EI_DATA=e_data),
                e_type=e_type, e_machine=e_machine, little=self.little))

        # create empty section entry
        undef_section = Elf32_Shdr()
        self.Elf.Shdr_table.append(undef_section)
        self.Elf.sections.append(b'')

        # create .shstrtab section and store its name in itself
        shstrtab = _Strtab()
        shstrtab_name = shstrtab.append('.shstrtab')

        # add .shstrtab into section header and section list
        shstrtab_hdr = Elf32_Shdr(sh_name=shstrtab_name, sh_type=SHT.SHT_STRTAB,
                sh_addralign=1)
        self.Elf.Shdr_table.append(shstrtab_hdr)
        self.Elf.sections.append(shstrtab) # this is ok, as long as shstrtab has
        # bytes() implementation

        # adjust e_shstrndx
        self.Elf.Ehdr.e_shstrndx = len(self.Elf.Shdr_table) - 1

        # add dummy program header
        if e_type in [ET.ET_EXEC, ET.ET_DYN]:
            self._append_segment(ptype=PT.PT_LOAD, vaddr=0, paddr=0,
                    file_size=0, mem_size=0, flags=int(PF.PF_R)|int(PF.PF_X))

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
        ret = ELF(None, None, None, None)
        ret.Elf, b = Elf32.from_bytes(b)
        ret.little = ret.Elf.little
        return ret, b

    def from_file(filename):
        """Deserializes ELF from filesystem"""
        fp = os.open(filename, os.O_RDONLY)
        file_size = os.fstat(fp).st_size
        b = os.read(fp, file_size)
        os.close(fp)

        return ELF.from_bytes(b)

    def get_section_by_name(self, sec_name):
        """Returns section header and content as tuple, based on their name"""
        if isinstance(sec_name, str):
            sec_name = bytes(sec_name, 'utf-8')
        elif not isinstance(sec_name, bytes):
            sec_name = bytes(sec_name)
        shstrtab_idx = self.Elf.Ehdr.e_shstrndx
        shstrtab_hdr = self.Elf.Shdr_table[shstrtab_idx]
        shstrtab = self.Elf.sections[shstrtab_idx]

        # shortcut if looking for .shstrtab
        if sec_name is '.shstrtab':
            return (shstrtab_hdr, shstrtab)

        # find string in .shstrtab
        name_off = shstrtab.find(sec_name)
        if name_off is -1:
            raise Exception('Section "%s" not in ELF' % \
                    sec_name.decode('utf-8'))

        # find header with sh_name equal offset
        for i, shdr in enumerate(self.Elf.Shdr_table):
            if shdr.sh_name == name_off:
                section = self.Elf.sections[i]
                return (shdr, section)
        raise Exception('Section "%s" found in .shstrtab at offset %d, but no'\
                'header with that name found. ELF internal structure '\
                'damaged.' % (sec_name.decode('utf-8'), name_off))

    def _append_section(self, sec_name, sec_data, sec_addr,
            sh_type=SHT.SHT_PROGBITS, sh_flags=0, sh_link=0, sh_info=0,
            sh_addralign=1, sh_entsize=0):
        if isinstance(sec_data, str):
            sec_data = bytes(sec_data, 'utf-8')

        # find .shstrtab
        shstrtab_hdr, shstrtab = self.get_section_by_name('.shstrtab')

        # create entry in section name section
        if not isinstance(shstrtab, _Strtab):
            shstrtab = _Strtab(shstrtab)
        self.Elf.sections[self.Elf.Ehdr.e_shstrndx] = shstrtab # FIXME: bad hack
        name_off = shstrtab.append(sec_name)

        # craft Shdr
        shdr = Elf32_Shdr(sh_name=name_off, sh_type=sh_type,
                sh_flags=sh_flags, sh_addr=sec_addr, sh_offset=0,
                sh_size=len(sec_data), sh_link=sh_link, sh_info=sh_info,
                sh_addralign=sh_addralign, sh_entsize=sh_entsize,
                little=self.little)

        # save current section index
        ret = len(self.Elf.Shdr_table)

        # check header - blob consistency
        if len(self.Elf.sections) is not ret:
            raise Exception('section header list and section list are '\
                    'inconsistent. Automatic section appending impossible')

        # add header to ELF
        self.Elf.Shdr_table.append(shdr)

        # add section to list
        self.Elf.sections.append(sec_data)

        return ret

    def append_section(self, sec_name, sec_data, sec_addr):
        """Add new section to ELF file

        Name is automatically appended to .shstrtab section. Return value is ID
        of newly added section"""
        return self._append_section(sec_name, sec_data, sec_addr,
                sh_type=SHT.SHT_PROGBITS, sh_flags=0, sh_link=0, sh_info=0,
                sh_addralign=1, sh_entsize=0)

    def append_special_section(self, sec_name):
        """Add new special section to ELF file

        This function allows to add one of the special, structured sections to
        ELF file. Name is automatically appended to .shstrtab section. Return
        value is ID of newly added section"""
        # sec_name should always by bytes
        if isinstance(sec_name, str):
            sec_name = bytes(sec_name, 'utf-8')

        if sec_name == b'.strtab':
            # create new string table
            return self._append_section(sec_name, _Strtab(), 0,
                    sh_type=SHT.SHT_STRTAB)
        elif sec_name == b'.symtab':
            # find id of .strtab
            strtab_hdr, strtab = self.get_section_by_name('.strtab')
            strtab_id = self.Elf.Shdr_table.index(strtab_hdr)

            # create new symbol table
            return self._append_section(sec_name, _Symtab(), 0,
                    sh_type=SHT.SHT_SYMTAB, sh_link=strtab_id, sh_info=0,
                    sh_addralign=4, sh_entsize=len(Elf32_Sym()))

        raise Exception('%s is not a special section name or is not ' \
                'supported yet' % sec_name)

    def append_segment(self, sec_id, addr=None, mem_size=-1, flags='rwx'):
        """Add new program header, desribing segment in memory

        This function is for executable and shared objects only. On other types
        of ELFs causes exception. Currently appended segment can only be of type
        PT_LOAD. Return value is ID of newly added segment
            sec_id   - id of section already describing this segment
            addr     - virtual address at which segment will be loaded
            mem_size - size of segment after loading into memory"""
        if self.Elf.Ehdr.e_type not in [ET.ET_EXEC, ET.ET_DYN]:
            raise Exception('ELF type is not executable neither shared (e_type'\
                    ' is %s)' % self.hdr.e_type)

        # extract section from section list
        Shdr = self.Elf.Shdr_table[sec_id]

        # set address to this of section linked if default
        if addr is None:
            addr = Shdr.sh_addr

        # set memory size to this of section linked if default
        if mem_size == -1:
            mem_size = Shdr.sh_size

        # create p_flags, based on flags parameter
        # FIXME: if flags is instance of bitmap
        p_flags = 0
        if 'r' in flags:
            p_flags |= PF.PF_R
        if 'w' in flags:
            p_flags |= PF.PF_W
        if 'x' in flags:
            p_flags |= PF.PF_X

        # call internal adder interface
        return self._append_segment(ptype=PT.PT_LOAD, vaddr=addr, paddr=0,
                file_size=Shdr.sh_size, mem_size=mem_size, flags=p_flags)

    def _append_segment(self, ptype, vaddr, paddr, file_size, mem_size, flags=0):
        # create instance of Phdr
        Phdr = Elf32_Phdr(p_type=ptype, p_offset=0, p_vaddr=vaddr,
                p_paddr=paddr, p_filesz=file_size, p_memsz=mem_size,
                p_flags=flags, p_align=1, little=self.little)

        # add Phdr to elf object
        ret = len(self.Elf.Phdr_table)
        self.Elf.Phdr_table.append(Phdr)
        return ret

    def append_symbol(self, sym_name, sym_section, sym_offset, sym_size,
            sym_binding=STB.STB_LOCAL, sym_type=STT.STT_NOTYPE,
            sym_visibility=STV.STV_DEFAULT):
        """Append new symbol to symbol table

        Creates symbol table, if necessary, and adds new symbol name to symbol
        string table and symbol descriptor to symbol table.
            sym_name    - name of symbol as str or bytes, or None if unnamed
            sym_section - number of section, where symbol is located
            sym_offset  - location of symbol from start of the section
            sym_size    - size of the symbol in bytes"""

        if not isinstance(sym_binding, STB):
            raise Exception('Symbol binding not of type STB, %s given' %
                    type(sym_binding).__name__)

        if not isinstance(sym_type, STT):
            raise Exception('Symbol type not of type STT, %s given' %
                    type(sym_type).__name__)

        if not isinstance(sym_visibility, STV):
            raise Exception('Symbol visibility not of type STV, %s given' %
                    type(sym_visibility).__name__)

        # find .strtab, name will be stored there
        try:
            strtab_hdr, strtab = self.get_section_by_name('.strtab')
        except:
            # strtab not found, create
            self.append_special_section('.strtab')
            strtab_hdr, strtab = self.get_section_by_name('.strtab')

        # find .symbtab for storing the symbol structure
        try:
            symtab_hdr, symtab = self.get_section_by_name('.symtab')
        except:
            # symtab not found, create
            self.append_special_section('.symtab')
            symtab_hdr, symtab = self.get_section_by_name('.symtab')

        # convert to _Strtab
        if not isinstance(strtab, _Strtab):
            strtab = _Strtab(strtab)
            strtab_id = self.Elf.Shdr_table.index(strtab_hdr)
            self.Elf.sections[strtab_id] = strtab # FIXME: bad hack

        # convert to _Symtab
        if not isinstance(symtab, _Symtab):
            symtab = _Symtab(symtab)
            symtab_id = self.Elf.Shdr_table.index(symtab_hdr)
            self.Elf.sections[symtab_id] = symtab # FIXME: bad hack

        # add symbol name to .strtab
        if sym_name is None:
            sym_off = 0
        else:
            sym_off = strtab.append(sym_name)

        # build st_info
        st_info = (int(sym_type) & 0xf) | (int(sym_binding) << 4)

        # build st_other
        st_other = int(sym_visibility) & 0x3

        # create new symbol structure
        sym = Elf32_Sym(sym_off, sym_offset, sym_size, st_info, st_other,
                sym_section, little=self.little)

        # add symbol to symbol table
        sym_id = symtab.append(sym)

        # if local update sh_info to symbol id plus one
        symtab_hdr.sh_info = sym_id + 1
