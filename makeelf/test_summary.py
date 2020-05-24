#!/usr/bin/env python3
from makeelf.elf import *
from test_elf import *
from test_elfsect import *
from test_elfstruct import *
import sys

classes = [
        'Elf32_e_ident',
        'Elf32_Ehdr',
        'Elf32_Phdr',
        'Elf32_Shdr',
        'Elf32',
        'Elf32_Dyn',
        'Elf32_Sym',
        ]

tests = ['str', 'repr', 'len', 'bytes', 'from_bytes']

def namelen():
    maxlen = 0
    for c in classes:
        l = len(c)
        if l > maxlen:
            maxlen = l
    return maxlen

def main():
    # header
    print('| {h:<{n}} | '.format(h='Class', n=namelen()), end='')
    for t in tests:
        print('{t} | '.format(t=t), end='')
    print()
    # separator
    print('|-{h:-<{n}}'.format(h='-', n=namelen()), end='')
    for t in tests:
        print('-|-{t:-<{n}}'.format(t='-', n=len(t)), end='')
    print('-|')
    # row for each class
    for c in classes:
        print('| {c:<{n}} | '.format(c=c, n=namelen()), end='')
        for t in tests:
            result = '?'
            tc = '{c}Tests'.format(c=c)
            c_obj = None
            try:
                c_obj = getattr(sys.modules[__name__], tc)
            except:
                result = '.'
            t_obj = None
            try:
                if c_obj is not None:
                    t_obj = c_obj.__dict__['test_{t}'.format(t=t)]
            except:
                result = '.'
            try:
                if t_obj is not None:
                    t_obj(c_obj())
                    result = '+'
            except Exception as e:
                result = '-'
            print('{t:<{n}} | '.format(t=result, n=len(t)), end='')
        print()
    pass

if __name__ == '__main__':
    main()
