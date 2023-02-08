#!/usr/bin/env python3
## \file elfstruct.py
#  \brief Classes for ELF file serialization/deserialization
from makeelf.type.enum import Enum
from makeelf.type.align import align,unalign
from makeelf.type.uint8 import uint8
from makeelf.type.uint16 import uint16
from makeelf.type.uint32 import uint32
import makeelf.utils

## \class ELFCLASS
#  \brief File class
class ELFCLASS(Enum):
    """EI_CLASS enumeration"""
    ELFCLASSNONE = 0
    ELFCLASS32 = 1
    ELFCLASS64 = 2


## \class ELFDATA
#  \brief Data encoding
class ELFDATA(Enum):
    """EI_DATA enumeration"""
    ELFDATANONE = 0
    ## File is little-endian
    ELFDATA2LSB = 1
    ## File is big-endian
    ELFDATA2MSB = 2


## \class EV
#  \brief File version
class EV(Enum):
    """EI_VERSION enumeration"""
    EV_NONE = 0
    EV_CURRENT = 1


## \class ELFOSABI
#  \brief Operating system/ABI identification
class ELFOSABI(Enum):
    """EI_OSABI enumeration"""
    ELFOSABI_NONE = 0
    ELFOSABI_HPUX = 1
    ELFOSABI_NETBSD = 2
    ELFOSABI_GNU = 3
    ## ELFOSABI_LINUX is an alias for ELFOSABI_GNU.
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
    ## A GNU extension for the ARM.
    ELFOSABI_ARM = 97
    ## A GNU extension for the MSP.
    ELFOSABI_STANDALONE = 255


## \class Elf32_e_ident
#  \brief ELF Identification
class Elf32_e_ident:

    def __init__(self, EI_MAG=b'\x7fELF', EI_CLASS=ELFCLASS.ELFCLASS32,
            EI_DATA=ELFDATA.ELFDATA2MSB, EI_VERSION=EV.EV_CURRENT,
            EI_OSABI=ELFOSABI.ELFOSABI_NONE, little=False):
        if isinstance(EI_MAG, bytes):
            ## ELF magic value
            #  \details Should be '^?ELF'
            self.EI_MAG = EI_MAG
            # TODO: check if valid and signal someone if invalid
        else:
            raise Exception('EI_MAG: wrong type: %s' % type(EI_MAG).__name__)

        if isinstance(EI_CLASS, ELFCLASS):
            ## Value of type \link ELFCLASS \endlink
            self.EI_CLASS = EI_CLASS
        elif EI_CLASS in map(int, ELFCLASS):
            self.EI_CLASS = ELFCLASS(EI_CLASS)
        else:
            self.EI_CLASS = ELFCLASS[EI_CLASS]

        if isinstance(EI_DATA, ELFDATA):
            ## Value of type \link ELFDATA \endlink
            self.EI_DATA = EI_DATA
        elif EI_DATA in map(int, ELFDATA):
            self.EI_DATA = ELFDATA(EI_DATA)
        else:
            self.EI_DATA = ELFDATA[EI_DATA]

        if isinstance(EI_VERSION, EV):
            ## Value of type \link EV \endlink
            self.EI_VERSION = EI_VERSION
        elif EI_VERSION in map(int, EV):
            self.EI_VERSION = EV(EI_VERSION)
        else:
            self.EI_VERSION = EV[EI_VERSION]

        if isinstance(EI_OSABI, ELFOSABI):
            ## Value of type \link ELFOSABI \endlink
            self.EI_OSABI = EI_OSABI
        elif EI_OSABI in map(int, ELFOSABI):
            self.EI_OSABI = ELFOSABI(EI_OSABI)
        else:
            self.EI_OSABI = ELFOSABI[EI_OSABI]

        ## Header endianness indicator
        #  \details Is true, if header values are meant to be stored as
        #  little-endian or false otherwise
        self.little = little # should not be used, but for consistency set it

    def __str__(self):
        EI_MAG = self.EI_MAG
        if EI_MAG == b'\x7fELF':
            EI_MAG = "'^?ELF'"
        return '{EI_MAG=%s, EI_CLASS=%s, EI_DATA=%s, EI_VERSION=%s, '\
                'EI_OSABI=%s}' % (EI_MAG, self.EI_CLASS, self.EI_DATA,
                        self.EI_VERSION, self.EI_OSABI)

    def __repr__(self):
        return '%s(%s, %s, %s, %s, %s)' % (type(self).__name__, repr(self.EI_MAG),
                self.EI_CLASS, self.EI_DATA, self.EI_VERSION,
                self.EI_OSABI)

    def __eq__(self, rhs):
        # NOTE: little is ignored, is it wrong?
        return type(self) == type(rhs) and \
                self.EI_MAG == rhs.EI_MAG and \
                self.EI_CLASS == rhs.EI_CLASS and \
                self.EI_DATA == rhs.EI_DATA and \
                self.EI_VERSION == rhs.EI_VERSION and \
                self.EI_OSABI == rhs.EI_OSABI

    def __bytes__(self):
        packet = self.EI_MAG + bytes(self.EI_CLASS) + bytes(self.EI_DATA) + \
                bytes(self.EI_VERSION) + bytes(self.EI_OSABI)
        return align(packet, 16)

    def from_bytes(b):
        saved_b = b
        EI_MAG, b = (b[:4], b[4:])
        EI_CLASS, b = ELFCLASS.from_bytes(b)
        EI_DATA, b = ELFDATA.from_bytes(b)
        EI_VERSION, b = EV.from_bytes(b)
        EI_OSABI, b = ELFOSABI.from_bytes(b)
        b = unalign(saved_b, 16)
        return Elf32_e_ident(EI_MAG=EI_MAG, EI_CLASS=EI_CLASS, EI_DATA=EI_DATA,
                EI_VERSION=EI_VERSION, EI_OSABI=EI_OSABI), b

    def __len__(self):
        return len(bytes(self))


## \class ET
#  \brief Object file type
class ET(Enum):
    """e_type enumeration"""
    ET_NONE = 0
    ET_REL = 1
    ET_EXEC = 2
    ET_DYN = 3
    ET_CORE = 4
    ET_LOOS = 0xfe00
    ET_HIOS = 0xfeff
    ET_LOPROC = 0xff00
    ET_HIPROC = 0xffff


## \class EM
#  \brief Machine type
class EM(Enum):
    """e_machine enumeration"""
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
    EM_OLD_SPARCV9 = 11
    EM_res011 = 11
    EM_res012 = 12
    EM_res013 = 13
    EM_res014 = 14
    EM_PARISC = 15
    EM_res016 = 16
    EM_PPC_OLD = 17
    EM_VPP550 = 17
    EM_SPARC32PLUS = 18
    EM_960 = 19
    EM_PPC = 20
    EM_PPC64 = 21
    EM_S390 = 22
    EM_SPU = 23
    EM_res024 = 24
    EM_res025 = 25
    EM_res026 = 26
    EM_res027 = 27
    EM_res028 = 28
    EM_res029 = 29
    EM_res030 = 30
    EM_res031 = 31
    EM_res032 = 32
    EM_res033 = 33
    EM_res034 = 34
    EM_res035 = 35
    EM_V800 = 36
    EM_FR20 = 37
    EM_RH32 = 38
    EM_MCORE = 39
    EM_RCE = 39
    EM_ARM = 40
    EM_OLD_ALPHA = 41
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
    EM_ARC_COMPACT = 93
    EM_XTENSA = 94
    EM_SCORE_OLD = 95
    EM_VIDEOCORE = 95
    EM_TMM_GPP = 96
    EM_NS32K = 97
    EM_TPC = 98
    EM_PJ_OLD = 99
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
    EM_EXCESS = 111
    EM_DXP = 112
    EM_ALTERA_NIOS2 = 113
    EM_CRX = 114
    EM_CR16_OLD = 115
    EM_XGATE = 115
    EM_C166 = 116
    EM_M16C = 117
    EM_DSPIC30F = 118
    EM_CE = 119
    EM_M32C = 120
    EM_res121 = 121
    EM_res122 = 122
    EM_res123 = 123
    EM_res124 = 124
    EM_res125 = 125
    EM_res126 = 126
    EM_res127 = 127
    EM_res128 = 128
    EM_res129 = 129
    EM_res130 = 130
    EM_TSK3000 = 131
    EM_RS08 = 132
    EM_res133 = 133
    EM_ECOG2 = 134
    EM_SCORE = 135
    EM_SCORE7 = 135
    EM_DSP24 = 136
    EM_VIDEOCORE3 = 137
    EM_LATTICEMICO32 = 138
    EM_SE_C17 = 139
    EM_TI_C6000 = 140
    EM_TI_C2000 = 141
    EM_TI_C5500 = 142
    EM_res143 = 143
    EM_TI_PRU = 144
    EM_res145 = 145
    EM_res146 = 146
    EM_res147 = 147
    EM_res148 = 148
    EM_res149 = 149
    EM_res150 = 150
    EM_res151 = 151
    EM_res152 = 152
    EM_res153 = 153
    EM_res154 = 154
    EM_res155 = 155
    EM_res156 = 156
    EM_res157 = 157
    EM_res158 = 158
    EM_res159 = 159
    EM_MMDSP_PLUS = 160
    EM_CYPRESS_M8C = 161
    EM_R32C = 162
    EM_TRIMEDIA = 163
    EM_QDSP6 = 164
    EM_8051 = 165
    EM_STXP7X = 166
    EM_NDS32 = 167
    EM_ECOG1 = 168
    EM_ECOG1X = 168
    EM_MAXQ30 = 169
    EM_XIMO16 = 170
    EM_MANIK = 171
    EM_CRAYNV2 = 172
    EM_RX = 173
    EM_METAG = 174
    EM_MCST_ELBRUS = 175
    EM_ECOG16 = 176
    EM_CR16 = 177
    EM_ETPU = 178
    EM_SLE9X = 179
    EM_L1OM = 180
    EM_K1OM = 181
    EM_INTEL182 = 182
    EM_AARCH64 = 183
    EM_ARM184 = 184
    EM_AVR32 = 185
    EM_STM8 = 186
    EM_TILE64 = 187
    EM_TILEPRO = 188
    EM_MICROBLAZE = 189
    EM_CUDA = 190
    EM_TILEGX = 191
    EM_CLOUDSHIELD = 192
    EM_COREA_1ST = 193
    EM_COREA_2ND = 194
    EM_ARC_COMPACT2 = 195
    EM_OPEN8 = 196
    EM_RL78 = 197
    EM_VIDEOCORE5 = 198
    EM_78K0R = 199
    EM_56800EX = 200
    EM_BA1 = 201
    EM_BA2 = 202
    EM_XCORE = 203
    EM_MCHP_PIC = 204
    EM_INTELGT = 205
    EM_INTEL206 = 206
    EM_INTEL207 = 207
    EM_INTEL208 = 208
    EM_INTEL209 = 209
    EM_KM32 = 210
    EM_KMX32 = 211
    EM_KMX16 = 212
    EM_KMX8 = 213
    EM_KVARC = 214
    EM_CDP = 215
    EM_COGE = 216
    EM_COOL = 217
    EM_NORC = 218
    EM_CSR_KALIMBA = 219
    EM_Z80 = 220
    EM_VISIUM = 221
    EM_FT32 = 222
    EM_MOXIE = 223
    EM_AMDGPU = 224
    EM_RISCV = 243
    EM_LANAI = 244
    EM_CEVA = 245
    EM_CEVA_X2 = 246
    EM_BPF = 247
    EM_GRAPHCORE_IPU = 248
    EM_IMG1 = 249
    EM_NFP = 250
    EM_VE = 251
    EM_CSKY = 252
    EM_ARC_COMPACT3_64 = 253
    EM_MCS6502 = 254
    EM_ARC_COMPACT3 = 255
    EM_KVX = 256
    EM_65816 = 257
    EM_LOONGARCH = 258
    EM_KF32 = 259
    EM_U16_U8CORE = 260
    EM_TACHYUM = 261
    EM_56800EF = 262
    EM_AVR_OLD = 0x1057
    EM_MSP430_OLD = 0x1059
    EM_MT = 0x2530
    EM_CYGNUS_FR30 = 0x3330
    EM_WEBASSEMBLY = 0x4157
    EM_S12Z = 0x4DEF
    EM_DLX = 0x5aa5
    EM_CYGNUS_FRV = 0x5441
    EM_XC16X = 0x4688
    EM_CYGNUS_D10V = 0x7650
    EM_CYGNUS_D30V = 0x7676
    EM_IP2K_OLD = 0x8217
    EM_CYGNUS_POWERPC = 0x9025
    EM_ALPHA = 0x9026
    EM_CYGNUS_M32R = 0x9041
    EM_CYGNUS_V850 = 0x9080
    EM_S390_OLD = 0xa390
    EM_XTENSA_OLD = 0xabc7
    EM_XSTORMY16 = 0xad45
    EM_CYGNUS_MN10300 = 0xbeef
    EM_CYGNUS_MN10200 = 0xdead
    EM_M32C_OLD = 0xFEB0
    EM_IQ2000 = 0xFEBA
    EM_NIOS32 = 0xFEBB
    EM_CYGNUS_MEP = 0xF00D
    EM_MOXIE_OLD = 0xFEED
    EM_MICROBLAZE_OLD = 0xbaab
    EM_ADAPTEVA_EPIPHANY = 0x1223
    EM_OPENRISC = EM_OR1K
    EM_CSKY_OLD = EM_MCORE


## \class Elf32_Ehdr
#  \brief ELF Header
class Elf32_Ehdr:

    def __init__(self, e_ident=None, e_type=ET.ET_REL, e_machine=EM.EM_NONE,
            e_version=1, e_entry=0, e_phoff=0, e_shoff=0, e_flags=0,
            e_ehsize=0x34, e_phentsize=0, e_phnum=0, e_shentsize=0, e_shnum=0,
            e_shstrndx=0, little=False):

        if e_ident is None:
            ## Value of type \link Elf32_e_ident \endlink
            self.e_ident = Elf32_e_ident()
        else:
            self.e_ident = e_ident

        if isinstance(e_type, ET):
            ## Value of type \link ET \endlink
            self.e_type = e_type
        elif e_type in map(int, ET):
            self.e_type = EM(e_type)
        else:
            self.e_type = ET[e_type]

        if isinstance(e_machine, EM):
            ## Value of type \link EM \endlink
            self.e_machine = e_machine
        elif e_machine in map(int, EM):
            self.e_machine = EM(e_machine)
        else:
            self.e_machine = EM[e_machine]

        ## Value of type \link EV \endlink
        self.e_version = e_version
        ## Program entry point
        self.e_entry = e_entry
        ## Program Header offset in file
        self.e_phoff = e_phoff
        ## Section Header offset in file
        self.e_shoff = e_shoff
        ## Processor-specific flags
        self.e_flags = e_flags
        ## ELF Header size
        self.e_ehsize = e_ehsize
        ## Program Header entry size
        self.e_phentsize = e_phentsize
        ## Program Header entry count
        self.e_phnum = e_phnum
        ## Section Header entry size
        self.e_shentsize = e_shentsize
        ## Section Header entry count
        self.e_shnum = e_shnum
        ## Index of .shstrtab section in section table
        self.e_shstrndx = e_shstrndx

        ## Header endianness indicator
        #  \details Is true, if header values are meant to be stored as
        #  little-endian or false otherwise
        self.little = little
        if self.e_ident.EI_DATA is ELFDATA.ELFDATA2LSB:
            # overriding explicit value for header consistency
            self.little = True

    def __str__(self):
        return '{e_ident=%s, e_type=%s, e_machine=%s, e_version=%s, '\
    'e_entry=%s, e_phoff=%s, e_shoff=%s, e_flags=%s, e_ehsize=%s, '\
    'e_phentsize=%s, e_phnum=%s, e_shentsize=%s, e_shnum=%s, '\
                'e_shstrndx=%s}' % (self.e_ident, self.e_type, self.e_machine,
                        self.e_version, self.e_entry, self.e_phoff,
                        self.e_shoff, self.e_flags, self.e_ehsize,
                        self.e_phentsize, self.e_phnum, self.e_shentsize,
                        self.e_shnum, self.e_shstrndx)

    def __repr__(self):
        return '%s(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)' % \
    (type(self).__name__, repr(self.e_ident), self.e_type, self.e_machine,
            self.e_version, self.e_entry, self.e_phoff, self.e_shoff,
            self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum,
            self.e_shentsize, self.e_shnum, self.e_shstrndx)

    def __eq__(self, rhs):
        # NOTE: little is ignored, is it wrong?
        return type(self) == type(rhs) and \
                self.e_ident == rhs.e_ident and \
                self.e_type == rhs.e_type and \
                self.e_machine == rhs.e_machine and \
                self.e_version == rhs.e_version and \
                self.e_entry == rhs.e_entry and \
                self.e_phoff == rhs.e_phoff and \
                self.e_shoff == rhs.e_shoff and \
                self.e_flags == rhs.e_flags and \
                self.e_ehsize == rhs.e_ehsize and \
                self.e_phentsize == rhs.e_phentsize and \
                self.e_phnum == rhs.e_phnum and \
                self.e_shentsize == rhs.e_shentsize and \
                self.e_shnum == rhs.e_shnum and \
                self.e_shstrndx == rhs.e_shstrndx

    def __bytes__(self):
        little = self.little
        e_type = bytes(self.e_type)
        e_machine = bytes(self.e_machine)
        e_version = uint32(self.e_version, little)
        e_entry = uint32(self.e_entry, little)
        e_phoff = uint32(self.e_phoff, little)
        e_shoff = uint32(self.e_shoff, little)
        e_flags = uint32(self.e_flags, little)
        e_ehsize = uint16(self.e_ehsize, little)
        e_phentsize = uint16(self.e_phentsize, little)
        e_phnum = uint16(self.e_phnum, little)
        e_shentsize = uint16(self.e_shentsize, little)
        e_shnum = uint16(self.e_shnum, little)
        e_shstrndx = uint16(self.e_shstrndx, little)
        if self.little:
            e_type = bytes(reversed(e_type))
            e_machine = bytes(reversed(e_machine))
        b = bytes(self.e_ident) + bytes(e_type) + bytes(e_machine) + \
                bytes(e_version) + bytes(e_entry) + bytes(e_phoff) + \
                bytes(e_shoff) + bytes(e_flags) + bytes(e_ehsize) + \
                bytes(e_phentsize) + bytes(e_phnum) + bytes(e_shentsize) + \
                bytes(e_shnum) + bytes(e_shstrndx)
        return b

    def from_bytes(b):
        e_ident, b = Elf32_e_ident.from_bytes(b)
        # througout this function we rely only on ELF header regarding
        # endianness
        little = e_ident.EI_DATA is ELFDATA.ELFDATA2LSB
        e_type, b = ET.from_bytes(b, little=little)
        e_machine, b = EM.from_bytes(b, little=little)
        # TODO: use Elf*_Word or similar to be able to create second header -
        # Elf64_Ehdr for amd64
        e_version, b = uint32.from_bytes(b, little=little)
        e_entry, b = uint32.from_bytes(b, little=little) # || 64b
        e_phoff, b = uint32.from_bytes(b, little=little) # || 64b
        e_shoff, b = uint32.from_bytes(b, little=little) # || 64b
        e_flags, b = uint32.from_bytes(b, little=little)
        e_ehsize, b = uint16.from_bytes(b, little=little)
        e_phentsize, b = uint16.from_bytes(b, little=little)
        e_phnum, b = uint16.from_bytes(b, little=little)
        e_shentsize, b = uint16.from_bytes(b, little=little)
        e_shnum, b = uint16.from_bytes(b, little=little)
        e_shstrndx, b = uint16.from_bytes(b, little=little)
        Ehdr = Elf32_Ehdr(e_ident=e_ident, e_type=e_type, e_machine=e_machine,
                e_version=e_version.integer, e_entry=e_entry.integer,
                e_phoff=e_phoff.integer, e_shoff=e_shoff.integer,
                e_flags=e_flags.integer, e_ehsize=e_ehsize.integer,
                e_phentsize=e_phentsize.integer, e_phnum=e_phnum.integer,
                e_shentsize=e_shentsize.integer, e_shnum=e_shnum.integer,
                e_shstrndx=e_shstrndx.integer)
        return Ehdr, b

    def __len__(self):
        return len(bytes(self))


## \class PT
#  \brief Segment Type
class PT(Enum):
    PT_NULL = 0
    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_INTERP = 3
    PT_NOTE = 4
    PT_SHLIB = 5
    PT_PHDR = 6
    PT_TLS = 7
    PT_LOOS = 0x60000000
    PT_HIOS = 0x6fffffff
    PT_LOPROC = 0x70000000
    PT_HIPROC = 0x7fffffff
    # The remaining values are not in the standard.
    ## Frame unwind information.
    PT_GNU_EH_FRAME = 0x6474e550
    PT_SUNW_EH_FRAME = 0x6474e550
    ## Stack flags.
    PT_GNU_STACK = 0x6474e551
    ## Read only after relocation.
    PT_GNU_RELRO = 0x6474e552
    ## Platform architecture compatibility information
    PT_ARM_ARCHEXT = 0x70000000
    ## Exception unwind tables
    PT_ARM_EXIDX = 0x70000001
    ## Register usage information.  Identifies one .reginfo section.
    PT_MIPS_REGINFO =0x70000000
    ## Runtime procedure table.
    PT_MIPS_RTPROC = 0x70000001
    ## .MIPS.options section.
    PT_MIPS_OPTIONS = 0x70000002
    ## .MIPS.abiflags section.
    PT_MIPS_ABIFLAGS = 0x70000003
    ## Platform architecture compatibility information
    PT_AARCH64_ARCHEXT = 0x70000000
    ## Exception unwind tables
    PT_AARCH64_UNWIND = 0x70000001
    ## 4k page table size
    PT_S390_PGSTE = 0x70000000


## \class PF
#  \brief Segment Flag Bits
class PF(Enum):
    # FIXME: should be bitmap in future, not enum
    PF_X = 0x01
    PF_W = 0x02
    PF_R = 0x04
    PF_MASKOS = 0x0ff00000
    PF_MASKPROC = 0xf0000000


## \class Elf32_Phdr
#  \brief Program Header
class Elf32_Phdr:

    def __init__(self, p_type=0, p_offset=0, p_vaddr=0, p_paddr=0, p_filesz=0,
                 p_memsz=0, p_flags=0, p_align=0, little=False, sections=None):
        ## Type of segment
        self.p_type = p_type
        ## Offset in file, where first byte of segment resides
        self.p_offset = p_offset
        ## Virtual address of segment in memory
        self.p_vaddr = p_vaddr
        ## Physical address of segment in memory
        self.p_paddr = p_paddr
        ## Size of segment in file
        self.p_filesz = p_filesz
        ## Size of segment in memory
        self.p_memsz = p_memsz
        ## Segment flags
        self.p_flags = p_flags
        ## Segment alignment
        #  \details Value of 0 or 1 means no aligment is required
        self.p_align = p_align

        ## Header endianness indicator
        #  \details Is true, if header values are meant to be stored as
        #  little-endian or false otherwise
        self.little = little

        ## Sections linked to this segment
        #  \details List of Section IDs contained within this segment
        self.sections = sections or []

    def __str__(self):
        return '{p_type=%s, p_offset=%s, p_vaddr=%s, p_paddr=%s, ' \
                'p_filesz=%s, p_memsz=%s, p_flags=%s, p_align=%s}' % \
                (self.p_type, self.p_offset, self.p_vaddr, self.p_paddr,
                        self.p_filesz, self.p_memsz, self.p_flags, self.p_align)

    def __repr__(self):
        return '%s(%s, %s, %s, %s, %s, %s, %s, %s)' % (type(self).__name__,
                self.p_type, self.p_offset, self.p_vaddr, self.p_paddr,
                self.p_filesz, self.p_memsz, self.p_flags, self.p_align)

    def __bytes__(self):
        p_type = uint32(self.p_type, little=self.little)
        p_offset = uint32(self.p_offset, little=self.little)
        p_vaddr = uint32(self.p_vaddr, little=self.little)
        p_paddr = uint32(self.p_paddr, little=self.little)
        p_filesz = uint32(self.p_filesz, little=self.little)
        p_memsz = uint32(self.p_memsz, little=self.little)
        p_flags = uint32(self.p_flags, little=self.little)
        p_align = uint32(self.p_align, little=self.little)

        return bytes(p_type) + bytes(p_offset) + bytes(p_vaddr) + \
                bytes(p_paddr) + bytes(p_filesz) + bytes(p_memsz) + \
                bytes(p_flags) + bytes(p_align)

    def from_bytes(b, little=False):
        p_type, b = uint32.from_bytes(b, little)
        p_offset, b = uint32.from_bytes(b, little)
        p_vaddr, b = uint32.from_bytes(b, little)
        p_paddr, b = uint32.from_bytes(b, little)
        p_filesz, b = uint32.from_bytes(b, little)
        p_memsz, b = uint32.from_bytes(b, little)
        p_flags, b = uint32.from_bytes(b, little)
        p_align, b = uint32.from_bytes(b, little)

        return Elf32_Phdr(p_type=p_type.integer, p_offset=p_offset.integer,
                p_vaddr=p_vaddr.integer, p_paddr=p_paddr.integer,
                p_filesz=p_filesz.integer, p_memsz=p_memsz.integer,
                p_flags=p_flags.integer, p_align=p_align.integer, little=little
                ), b

    def __len__(self):
        return len(bytes(self))


## \class SHT
#  \brief Section Types
class SHT(Enum):
    """Valid values for sh_type field"""
    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_RELA = 4
    SHT_HASH = 5
    SHT_DYNAMIC = 6
    SHT_NOTE = 7
    SHT_NOBITS = 8
    SHT_REL = 9
    SHT_SHLIB = 10
    SHT_DYNSYM = 11
    SHT_INIT_ARRAY = 14
    SHT_FINI_ARRAY = 15
    SHT_PREINIT_ARRAY = 16
    SHT_GROUP = 17
    SHT_SYMTAB_SHNDX = 18
    SHT_LOOS = 0x60000000
    SHT_HIOS = 0x6fffffff
    SHT_LOPROC = 0x70000000
    SHT_HIPROC = 0x7fffffff
    SHT_LOUSER = 0x80000000
    SHT_HIUSER = 0xffffffff
    SHT_RENESAS_INFO = 0xa0000000


## \class SHN
#  \brief Special Section Indexes
class SHN(Enum):
    SHN_UNDEF = 0
    SHN_LORESERVE = 0xff00
    SHN_LOPROC = 0xff00
    SHN_HIPROC = 0xff1f
    SHN_LOOS = 0xff20
    SHN_HIOS = 0xff3f
    SHN_ABS = 0xfff1
    SHN_COMMON = 0xfff2
    SHN_XINDEX = 0xffff
    SHN_HIRESERVE = 0xffff


## \class SHF
#  \brief Section Attribute Flags
class SHF(Enum):
    SHF_WRITE = 0x1
    SHF_ALLOC = 0x2
    SHF_EXECINSTR = 0x4
    SHF_MERGE = 0x10
    SHF_STRINGS = 0x20
    SHF_INFO_LINK = 0x40
    SHF_LINK_ORDER = 0x80
    SHF_OS_NONCONFORMING = 0x100
    SHF_GROUP = 0x200
    SHF_TLS = 0x400
    SHF_MASKOS = 0x0ff00000
    SHF_MASKPROC = 0xf0000000
    # TODO: will not be an enum, but bitmap, implement first


## \class Elf32_Shdr
#  \brief Section Header
class Elf32_Shdr:

    def __init__(self, sh_name=0, sh_type=SHT.SHT_NULL, sh_flags=0, sh_addr=0,
            sh_offset=0, sh_size=0, sh_link=0, sh_info=0, sh_addralign=0,
            sh_entsize=0, little=False):
        ## Offset of section name in .shstrtab
        self.sh_name = sh_name

        if isinstance(sh_type, SHT):
            ## Value of type \link SHT \endlink
            self.sh_type = sh_type
        elif sh_type in map(int, SHT):
            self.sh_type = SHT(sh_type)
        elif isinstance(sh_type, int):
            # TODO: log warning message
            self.sh_type = uint32(sh_type, little)
        else:
            self.sh_type = SHT[sh_type]

        ## Value of type \link SHF \endlink
        self.sh_flags = sh_flags
        ## Address of first byte of segment in memory
        self.sh_addr = sh_addr
        ## Address of first byte of segment in file
        self.sh_offset = sh_offset
        ## Size of section in file
        self.sh_size = sh_size
        ## Section type dependent value
        self.sh_link = sh_link
        ## Section type dependent value
        self.sh_info = sh_info
        ## Section alignment
        #  \details Value of 0 or 1 means no aligment is required
        self.sh_addralign = sh_addralign
        ## Entry size, if section holds fixed-size entries
        self.sh_entsize = sh_entsize

        ## Header endianness indicator
        #  \details Is true, if header values are meant to be stored as
        #  little-endian or false otherwise
        self.little = little

    def __str__(self):
        return '{sh_name=%s, sh_type=%s, sh_flags=%s, sh_addr=%s, '\
                'sh_offset=%s, sh_size=%s, sh_link=%s, sh_info=%s, '\
                'sh_addralign=%s, sh_entsize=%s}' % (self.sh_name, self.sh_type,
                        self.sh_flags, self.sh_addr, self.sh_offset,
                        self.sh_size, self.sh_link, self.sh_info,
                        self.sh_addralign, self.sh_entsize)

    def __repr__(self):
        return '%s(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)' % \
    (type(self).__name__, self.sh_name, self.sh_type, self.sh_flags,
            self.sh_addr, self.sh_offset, self.sh_size, self.sh_link,
            self.sh_info, self.sh_addralign, self.sh_entsize)

    def __bytes__(self):
        sh_name = uint32(self.sh_name, little=self.little)
        sh_type = bytes(self.sh_type)
        sh_flags = uint32(self.sh_flags, little=self.little)
        sh_addr = uint32(self.sh_addr, little=self.little)
        sh_offset = uint32(self.sh_offset, little=self.little)
        sh_size = uint32(self.sh_size, little=self.little)
        sh_link = uint32(self.sh_link, little=self.little)
        sh_info = uint32(self.sh_info, little=self.little)
        sh_addralign = uint32(self.sh_addralign, little=self.little)
        sh_entsize = uint32(self.sh_entsize, little=self.little)

        # make sure sh_type is enum, before reversing bytes
        # other way it may be already reversed
        if self.little and isinstance(self.sh_type, SHT):
            sh_type = bytes(reversed(sh_type))

        return bytes(sh_name) + bytes(sh_type) + bytes(sh_flags) + \
                bytes(sh_addr) + bytes(sh_offset) + bytes(sh_size) + \
                bytes(sh_link) + bytes(sh_info) + bytes(sh_addralign) + \
                bytes(sh_entsize)

    def from_bytes(b, little=False):
        sh_name, b = uint32.from_bytes(b, little=little)
        sh_type, b = uint32.from_bytes(b, little=little)
        sh_flags, b = uint32.from_bytes(b, little=little)
        sh_addr, b = uint32.from_bytes(b, little=little)
        sh_offset, b = uint32.from_bytes(b, little=little)
        sh_size, b = uint32.from_bytes(b, little=little)
        sh_link, b = uint32.from_bytes(b, little=little)
        sh_info, b = uint32.from_bytes(b, little=little)
        sh_addralign, b = uint32.from_bytes(b, little=little)
        sh_entsize, b = uint32.from_bytes(b, little=little)

        return Elf32_Shdr(sh_name.integer, sh_type.integer, sh_flags.integer,
                sh_addr.integer, sh_offset.integer, sh_size.integer,
                sh_link.integer, sh_info.integer, sh_addralign.integer,
                sh_entsize.integer, little=little), b

    def __len__(self):
        return len(bytes(self))


## \class Elf32
#  \brief Complete ELF structure storage class
#  \details Allows to craft ELF file using low-level interfaces for manipulating
#  data fields and accessing headers contained inside. This class is not meant
#  to provide any abstraction on top of ELF structure
class Elf32:

    ##
    # \brief The constructor
    # \details Reconstructs new Elf32 object with all stored public members
    #
    # \param Ehdr ELF header
    # \param Phdr_table List of program headers
    # \param Shdr_table List of section headers
    # \param sections List of section contents
    # \param little Endianness of ELF file
    def __init__(self, Ehdr=None, Phdr_table=None, Shdr_table=None,
            sections=None, little=False):
        if Ehdr is None:
            Ehdr = Elf32_Ehdr()
        if Phdr_table is None:
            Phdr_table = []
        if Shdr_table is None:
            Shdr_table = []
        if sections is None:
            sections = []

        if isinstance(Ehdr, Elf32_Ehdr):
            ## Instance of \link Elf32_Ehdr \endlink
            self.Ehdr = Ehdr
        else:
            self.Ehdr = Ehdr.from_bytes(Ehdr)

        if isinstance(Phdr_table, list) and (len(Phdr_table) == 0) or (
                isinstance(Phdr_table[0], Elf32_Phdr)):
            ## List of instances of \link Elf32_Phdr \endlink
            self.Phdr_table = Phdr_table
        else:
            raise Exception('Phdr table must be a list of Elf32_Phdr objects')

        if isinstance(Shdr_table, list) and (len(Shdr_table) == 0) or (
                isinstance(Shdr_table[0], Elf32_Shdr)):
            ## List of instances of \link Elf32_Shdr \endlink
            self.Shdr_table = Shdr_table
        else:
            raise Exception('Shdr table must be a list of Elf32_Shdr objects')

        if isinstance(sections, list):
            ## List of section content
            #  \details Contains raw bytes objects or any type that can be
            #  converted using bytes function
            self.sections = sections
        else:
            raise Exception('Sections must be a list containing section content')

        self.little = little

    ##
    # \brief Convert to str
    # \details Useful for presenting contents to the user
    #
    # \return String in format: "{key=val, key2=val2}"
    def __str__(self):
        return '{Ehdr=%s, Phdr_table=%s, Shdr_table=%s, sections=%s}' % \
                (self.Ehdr, self.Phdr_table, self.Shdr_table, self.sections)

    ##
    # \brief String representation
    # \details Provides ability to recreate object using its constructor, from
    # Python CLI mode
    #
    # \return String in format: "Classname(param, param2)"
    def __repr__(self):
        return '%s(%s, %s, %s, %s)' % (type(self).__name__, self.Ehdr,
                self.Phdr_table, self.Shdr_table, self.sections)

    ##
    # \brief Serialization to bytes
    # \details Converts Python object to byte stream, ready to be saved to ELF
    # file
    #
    # \return Serialized object
    def __bytes__(self):
        headers = {}
        headers[0] = bytes(self.Ehdr)

        # Phdrs
        cursor = self.Ehdr.e_phoff
        for Phdr in self.Phdr_table:
            headers[cursor] = Phdr
            cursor += self.Ehdr.e_phentsize

        # Shdrs
        cursor = self.Ehdr.e_shoff
        for Shdr in self.Shdr_table:
            headers[cursor] = Shdr
            cursor += self.Ehdr.e_shentsize

        # sections
        for i, Shdr in enumerate(self.Shdr_table):
            if len(self.sections[i]) != 0:
                headers[Shdr.sh_offset] = self.sections[i]

        # find file size
        end_of_file = sorted(headers.keys())[-1]
        end_of_file += len(headers[end_of_file])

        # create and populate buffer
        b = bytes(end_of_file)
        for off in headers:
            # TODO: there's something wrong, when hdr is not bytes, but only
            # simulates it
            hdr = headers[off]
            if isinstance(hdr, list):
                hdr_as_bytes = b''
                for e in hdr:
                    hdr_as_bytes += bytes(e)
                hdr = hdr_as_bytes
            else:
                hdr = bytes(hdr)
            size = len(hdr)

            # expand to file size
            aligned = align(bytes(off) + hdr, end_of_file)

            # xor into b
            b = makeelf.utils.bytes_xor(b, aligned)
        return b

    ##
    # \brief Deserialization of object
    #
    # \param b bytes object with serialized data on the beginning
    # \param little endianness of data
    #
    # \return tuple of deserialized object and rest of bytes
    def from_bytes(b, little=False):
        blob = b
        Ehdr, b = Elf32_Ehdr.from_bytes(b)

        # pass endianness from Ehdr to other headers
        little = Ehdr.little

        # Program headers
        Phdr_a = []
        for i in range(Ehdr.e_phnum):
            Phdr, b = Elf32_Phdr.from_bytes(b, little)
            Phdr_a.append(Phdr)

        # Section headers
        Shdr_a = []
        b = blob[Ehdr.e_shoff:]
        for i in range(Ehdr.e_shnum):
            Shdr, b = Elf32_Shdr.from_bytes(b, little)
            Shdr_a.append(Shdr)

        # Sections
        sections = []
        # TODO: support of section content handlers, i.e. _Strtab, _Symtab
        for i, Shdr in enumerate(Shdr_a):
            first = Shdr.sh_offset
            last = first + Shdr.sh_size
            section = blob[first:last]
            sections.append(section)

        return Elf32(Ehdr, Phdr_a, Shdr_a, sections, little=Ehdr.little), None

    ##
    # \brief Length of object
    #
    # \return length of object
    def __len__(self):
        return len(bytes(self))


if __name__ == '__main__':
    # TODO: make some real tests
    print('tests')
    print('obj->file')
    e_ident = Elf32_e_ident(EI_OSABI=ELFOSABI.ELFOSABI_GNU)
    Ehdr = Elf32_Ehdr(e_ident=e_ident, e_machine=0xbaab)
    print(Ehdr)
    import os
    fd = os.open('out.elf', os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    os.write(fd, bytes(Ehdr))
    os.close(fd)
    print('file->obj')
    for file in ['microblaze_0.elf', 'rot13.elf']:
        print(file)
        fd = os.open(file, os.O_RDONLY)
        b = os.read(fd, 0xffff)
        os.close(fd)
        print(len(b))
        Ehdr, b = Elf32_Ehdr.from_bytes(b)
        print(Ehdr)
        print(b[:32])

    print('full parse microblaze_0.elf')
    fd = os.open('microblaze_0.elf', os.O_RDONLY)
    blob = os.read(fd, 0xffff)
    b = blob
    os.close(fd)

    # Ehdr
    Ehdr, b = Elf32_Ehdr.from_bytes(b)
    print(Ehdr)

    # Phdr
    Phdr_a = []
    for i in range(Ehdr.e_phnum):
        Phdr, b = Elf32_Phdr.from_bytes(b)
        Phdr_a.append(Phdr)
    print(' Phdr table:')
    for i, Phdr in enumerate(Phdr_a):
        print('Phdr #%d: %s' % (i, Phdr))

    # Shdr
    Shdr_a = []
    b = blob[Ehdr.e_shoff:]
    for i in range(Ehdr.e_shnum):
        Shdr, b = Elf32_Shdr.from_bytes(b)
        Shdr_a.append(Shdr)

    # .shstr
    Shdr_shstr = Shdr_a[Ehdr.e_shstrndx]
    shstr_start = Shdr_shstr.sh_offset
    shstr_end = shstr_start + Shdr_shstr.sh_size
    print(Shdr_shstr)
    shstr = blob[shstr_start:shstr_end]

    print(' Shdr table:')
    for i, Shdr in enumerate(Shdr_a):
        Shdr_name = shstr[Shdr.sh_name:]
        Shdr_name = Shdr_name[:Shdr_name.index(b'\x00')].decode('utf-8')
        print('Shdr #%d (%s): %s' % (i, Shdr_name, Shdr))

    print('Rewrite existing ELF from one file to another')
    fd = os.open('microblaze_0.elf', os.O_RDONLY)
    b = os.read(fd, 0xffff)
    os.close(fd)
    Elf,b=Elf32.from_bytes(b)
    print(Elf)
    fd=os.open('test.elf', os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    os.write(fd, bytes(Elf))
    os.close(fd)

    print('test')
    fd = os.open('microblaze_0.elf', os.O_RDONLY)
    src = os.read(fd, 0xffff)
    os.close(fd)
    fd = os.open('test.elf', os.O_RDONLY)
    dst = os.read(fd, 0xffff)
    os.close(fd)
    if src == dst:
        print('OK')
    else:
        print('FAIL')
