def bytes_xor(lhs, rhs):
    res = []
    for a, b in zip(lhs, rhs):
        res.append(a ^ b)
    return bytes(res)
