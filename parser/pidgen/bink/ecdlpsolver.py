try:
    from sage.all import *
except ImportError:
    print("Unable to load SageMath")

# def warnx(*args, **kwargs):
#    print(*args, file=sys.stderr, **kwargs)


# def tee(*output, file=None, **kwargs):
#    print(*output, file=sys.stdout, **kwargs)
#    if file is not None:
#        print(*output, file=file, **kwargs)


def btoi(bb):
    return int.from_bytes(bb, byteorder='little')


def rfactor(m, keysize, B):
    digits = len('%d' % (2 ^ keysize - 1))
    ff = ecm.find_factor(m, factor_digits=digits)  # Try to find a good candidate
    for f in ff:
        if f > 2 and f.is_prime() and not f * B:
            # warnx("ok for %d" % f)
            return True, [f]
    else:
        # warnx("bad run: %s" % ff)
        return False, ff


def parse_bink_data_with_sage(bink):
    curve = bink['curve']
    bink_header = bink['header']
    F = GF(curve['p'])
    # warnx("offs = %d, nb = %d, p = %x" % (offs, nb, p))
    a = F(curve['a'])
    b = F(curve['b'])
    bx = F(curve['g']['x'])
    by = F(curve['g']['y'])
    Kx = F(curve['pub']['x'])
    Ky = F(curve['pub']['y'])

    E = EllipticCurve(F, [0, 0, 0, a, b])
    # warnx(E)
    B = E(bx, by)
    K = E(Kx, Ky)

    # If we get here, we know B and K are on the curve.
    # Now get the order of the curve and then factorize it.

    n = E.order()
    # warnx("n = %d, now factoring..." % n)
    # Find L by just trying if any of the factors in f yield the point at infinity
    factors = []

    ok, values = rfactor(n, bink_header['hashlen'], B)
    while not ok:
        for value in values:
            ok, nl = rfactor(value, bink_header['keysize'], B)
            if ok:
                L = nl[0]
                break
            values.extend(nl)

    factors = [n // L, L]

    # warnx(factors)
    # warnx("Reduce the result of ECDLP Solver modulo %d" % L)
    # warnx("\n\njob input:\n\n")

    bink['curve']['n'] = L

    solver_input = ''
    solver_input += 'GF := GF(%d);\n' % curve['p']
    solver_input += 'E := EllipticCurve([GF|%d,%d]);\n' % (curve['a'], curve['b'])
    solver_input += 'G := E![%d,%d];\n' % (curve['g']['x'], curve['g']['y'])
    solver_input += 'K := E![%d,%d];\n' % (curve['pub']['x'], curve['pub']['y'])
    solver_input += '/*\n'
    solver_input += 'FactorCount:=%d;\n' % len(factors)
    for f in factors:
        solver_input += '%d;\n' % f
    solver_input += '*/'

    bink['solver_input'] = solver_input

    return bink


def parse(bink):
    bink_id_int = btoi(bink[0x00:0x04])
    bink_id = "%08x" % bink_id_int

    bink_header = {
        'identifier': btoi(bink[0x00:0x04]),
        'sizeof': btoi(bink[0x04:0x08]),
        'countof': btoi(bink[0x08:0x0C]),
        'checksum': btoi(bink[0x0C:0x10]),
        'version': btoi(bink[0x10:0x14]),
        'keysize': btoi(bink[0x14:0x18]),
        'hashlen': btoi(bink[0x18:0x1C]),
        'siglen': btoi(bink[0x1C:0x20]),
    }

    bink_values = bink[0x20:]
    if bink_header["version"] > 20020420:
        bink_values = bink[0x28:]
        bink_header['authlen'] = btoi(bink[0x20:0x24])
        bink_header['pidlen'] = btoi(bink[0x24:0x28])

    offs = bink_header["keysize"] * 4

    curve = {
        'p': btoi(bink_values[:offs]),
        'a': btoi(bink_values[offs:offs * 2]),
        'b': btoi(bink_values[offs * 2:offs * 3]),
        'g': {'x': btoi(bink_values[offs * 3:offs * 4]), 'y': btoi(bink_values[offs * 4:offs * 5])},
        'pub': {'x': btoi(bink_values[offs * 5:offs * 6]), 'y': btoi(bink_values[offs * 6:offs * 7])},
        'n': '',
        'priv': ''
    }

    output = {
        'bink_name': bink_id,
        'header': bink_header,
        'curve': curve,
    }

    output = parse_bink_data_with_sage(output)

    return output
