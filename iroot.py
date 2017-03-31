# https://rosettacode.org/wiki/Integer_roots#Python
def iroot(a,b):
    if b<2:return b
    a1=a-1
    c=1
    d=(a1*c+b//(c**a1))//a
    e=(a1*d+b//(d**a1))//a
    while c!=d and c!=e:
        c,d,e=d,e,(a1*e+b//(e**a1))//a
    return min(d,e)

import itertools
for x in range(0, 1000):
    print x
    xp = 1
    for p in range(1, 100):
        xp *= x
        r = iroot(p, xp)
        if x != r:
            print x, p, '->', xp, '->', r, '!=', x
