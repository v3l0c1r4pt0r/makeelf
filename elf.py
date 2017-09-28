#!/usr/bin/env python3
# Classes for ELF file serialization/deserialization
from enum import IntEnum

"""EI_CLASS enumeration"""
class ELFCLASS(IntEnum):
    ELFCLASSNONE = 0
    ELFCLASS32 = 1
    ELFCLASS64 = 2


"""EI_DATA enumeration"""
class ELFDATA(IntEnum):
    ELFDATANONE = 0
    ELFDATA2LSB = 1
    ELFDATA2MSB = 2


"""EI_VERSION enumeration"""
class EV(IntEnum):
    EV_NONE = 0
    EV_CURRENT = 1


"""EI_OSABI enumeration"""
class ELFOSABI(IntEnum):
    ELFOSABI_NONE = 0
    ELFOSABI_HPUX = 1
    ELFOSABI_NETBSD = 2
    ELFOSABI_GNU = 3
    # ELFOSABI_LINUX is an alias for ELFOSABI_GNU.
    ELFOSABI_LINUX = 3
    ELFOSABI_SOLARIS = 6
    ELFOSABI_AIX = 7
    ELFOSABI_IRIX = 8
    ELFOSABI_FREEBSD = 9
    ELFOSABI_TRU64 = 10
    ELFOSABI_MODESTO = 11
    ELFOSABI_OPENBSD = 12
    ELFOSABI_OPENVMS = 13
    ELFOSABI_NSK = 14
    ELFOSABI_AROS = 15
    # A GNU extension for the ARM.
    ELFOSABI_ARM = 97
    # A GNU extension for the MSP.
    ELFOSABI_STANDALONE = 255


class Elf32_e_ident:

    def __init__(self, EI_MAG=b'\x7fELF', EI_CLASS=ELFCLASS.ELFCLASS32,
            EI_DATA=ELFDATA.ELFDATA2MSB, EI_VERSION=EV.EV_CURRENT,
            EI_OSABI=ELFOSABI.ELFOSABI_NONE):
        pass


if __name__ == '__main__':
    elf = Elf32_Ehdr()
    print(elf)
    print('tests')
