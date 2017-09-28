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
        if isinstance(EI_MAG, bytes):
            self.EI_MAG = EI_MAG
            # TODO: check if valid and signal someone if invalid
        else:
            raise Exception('EI_MAG: wrong type: %s' % type(EI_MAG).__name__)

        if isinstance(EI_CLASS, ELFCLASS):
            self.EI_CLASS = EI_CLASS
        else:
            self.EI_CLASS = ELFCLASS[EI_CLASS]

        if isinstance(EI_DATA, ELFDATA):
            self.EI_DATA = EI_DATA
        else:
            self.EI_DATA = ELFDATA[EI_DATA]

        if isinstance(EI_VERSION, EV):
            self.EI_VERSION = EI_VERSION
        else:
            self.EI_VERSION = EV[EI_VERSION]

        if isinstance(EI_OSABI, ELFOSABI):
            self.EI_OSABI = EI_OSABI
        else:
            self.EI_OSABI = ELFOSABI[EI_OSABI]


"""e_type enumeration"""
class ET(IntEnum):
    ET_NONE = 0
    ET_REL = 1
    ET_EXEC = 2
    ET_DYN = 3
    ET_CORE = 4
    ET_LOOS = 0xfe00
    ET_HIOS = 0xfeff
    ET_LOPROC = 0xff00
    ET_HIPROC = 0xffff


"""e_machine enumeration"""
class EM(IntEnum):
    EM_NONE = 0
    EM_M32 = 1
    EM_SPARC = 2
    EM_386 = 3
    EM_68K = 4
    EM_88K = 5
    EM_IAMCU = 6
    EM_860 = 7
    EM_MIPS = 8
    EM_S370 = 9
    EM_MIPS_RS3_LE = 10
    # 11 was the old Sparc V9 ABI.
    # 12 through 14 are reserved.
    EM_PARISC = 15
    # 16 is reserved.
    # Some old PowerPC object files use 17.
    EM_VPP500 = 17
    EM_SPARC32PLUS = 18
    EM_960 = 19
    EM_PPC = 20
    EM_PPC64 = 21
    EM_S390 = 22
    # 23 through 35 are served.
    EM_V800 = 36
    EM_FR20 = 37
    EM_RH32 = 38
    EM_RCE = 39
    EM_ARM = 40
    EM_ALPHA = 41
    EM_SH = 42
    EM_SPARCV9 = 43
    EM_TRICORE = 44
    EM_ARC = 45
    EM_H8_300 = 46
    EM_H8_300H = 47
    EM_H8S = 48
    EM_H8_500 = 49
    EM_IA_64 = 50
    EM_MIPS_X = 51
    EM_COLDFIRE = 52
    EM_68HC12 = 53
    EM_MMA = 54
    EM_PCP = 55
    EM_NCPU = 56
    EM_NDR1 = 57
    EM_STARCORE = 58
    EM_ME16 = 59
    EM_ST100 = 60
    EM_TINYJ = 61
    EM_X86_64 = 62
    EM_PDSP = 63
    EM_PDP10 = 64
    EM_PDP11 = 65
    EM_FX66 = 66
    EM_ST9PLUS = 67
    EM_ST7 = 68
    EM_68HC16 = 69
    EM_68HC11 = 70
    EM_68HC08 = 71
    EM_68HC05 = 72
    EM_SVX = 73
    EM_ST19 = 74
    EM_VAX = 75
    EM_CRIS = 76
    EM_JAVELIN = 77
    EM_FIREPATH = 78
    EM_ZSP = 79
    EM_MMIX = 80
    EM_HUANY = 81
    EM_PRISM = 82
    EM_AVR = 83
    EM_FR30 = 84
    EM_D10V = 85
    EM_D30V = 86
    EM_V850 = 87
    EM_M32R = 88
    EM_MN10300 = 89
    EM_MN10200 = 90
    EM_PJ = 91
    EM_OR1K = 92
    EM_ARC_A5 = 93
    EM_XTENSA = 94
    EM_VIDEOCORE = 95
    EM_TMM_GPP = 96
    EM_NS32K = 97
    EM_TPC = 98
    # Some old picoJava object files use 99 (EM_PJ is correct).
    EM_SNP1K = 99
    EM_ST200 = 100
    EM_IP2K = 101
    EM_MAX = 102
    EM_CR = 103
    EM_F2MC16 = 104
    EM_MSP430 = 105
    EM_BLACKFIN = 106
    EM_SE_C33 = 107
    EM_SEP = 108
    EM_ARCA = 109
    EM_UNICORE = 110
    EM_ALTERA_NIOS2 = 113
    EM_CRX = 114
    EM_TI_PRU = 144
    EM_AARCH64 = 183
    EM_TILEGX = 191
    # The Morph MT.
    EM_MT = 0x2530
    # DLX.
    EM_DLX = 0x5aa5
    # FRV.
    EM_FRV = 0x5441
    # Infineon Technologies 16-bit microcontroller with C166-V2 core.
    EM_X16X = 0x4688
    # Xstorym16
    EM_XSTORMY16 = 0xad45
    # Renesas M32C
    EM_M32C = 0xfeb0
    # Vitesse IQ2000
    EM_IQ2000 = 0xfeba
    # NIOS
    EM_NIOS32 = 0xfebb
    # Old AVR objects used 0x1057 (EM_AVR is correct).
    # Old MSP430 objects used 0x1059 (EM_MSP430 is correct).
    # Old FR30 objects used 0x3330 (EM_FR30 is correct).
    # Old OpenRISC objects used 0x3426 and 0x8472 (EM_OR1K is correct).
    # Old D10V objects used 0x7650 (EM_D10V is correct).
    # Old D30V objects used 0x7676 (EM_D30V is correct).
    # Old IP2X objects used 0x8217 (EM_IP2K is correct).
    # Old PowerPC objects used 0x9025 (EM_PPC is correct).
    # Old Alpha objects used 0x9026 (EM_ALPHA is correct).
    # Old M32R objects used 0x9041 (EM_M32R is correct).
    # Old V850 objects used 0x9080 (EM_V850 is correct).
    # Old S/390 objects used 0xa390 (EM_S390 is correct).
    # Old Xtensa objects used 0xabc7 (EM_XTENSA is correct).
    # Old MN10300 objects used 0xbeef (EM_MN10300 is correct).
    # Old MN10200 objects used 0xdead (EM_MN10200 is correct).


class Elf32_Ehdr:

    def __init__(self, e_ident=None, e_type=ET.ET_REL, e_machine=EM.EM_NONE,
            e_version=1, e_entry=0, e_phoff=0, e_shoff=0, e_flags=0,
            e_ehsize=0x40, e_phentsize=0, e_phnum=0, e_shentsize=0, e_shnum=0,
            e_shstrndx=0):
        pass


if __name__ == '__main__':
    elf = Elf32_Ehdr()
    print(elf)
    print('tests')
