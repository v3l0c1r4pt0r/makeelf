#!/usr/bin/env python3
## \file align.py
#  \brief alignment function
from math import ceil

def align(b, alignment=4):
    """Returns bytes object aligned to specified number of bytes"""
    full = ceil(len(b) / alignment)
    diff = (full * alignment) - len(b)
    return b + bytes(diff)

def unalign(b, alignment=4):
    """Returns bytes after end of alignment to specified number of bytes"""
    return b[alignment:]
