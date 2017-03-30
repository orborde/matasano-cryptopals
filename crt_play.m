n1 = 881
n2 = 883
n1n2 = n1*n2

m = 200
m2 = m ** 2
m2n1n1 = mod(m2, n1n2)

a1 = mod(m2,n1)
a2 = mod(m2,n2)

a1_1 = mod((a1 + n1), n2)
d = a1_1 - a2
k = d / (a1 - a1_1)
rollabout = a1 + (k + 1) * n1
rollabout_mod_n1 = mod(rollabout, n1)
rollabout_mod_n2 = mod(rollabout, n2)
derived_m2 = rollabout ** (1/2)
