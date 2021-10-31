from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from sympy import randprime, nextprime, invert

p = randprime(2**1023, 2**1024)
q = nextprime(p)
n = p * q
e = 65537
phi = (p-1)*(q-1)
d = int(invert(e, phi))
key = RSA.construct((n, e, d, p, q))
rsa = PKCS1_OAEP.new(key)
print(n)
print(rsa.encrypt(open('./flag.txt', 'rb').read()))
