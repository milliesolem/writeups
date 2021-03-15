# Run this script in python 3.8 or newer

import base64
import hashlib

"""
Disclaimer: I did not solve this challenge under the CTF (although I was close). This was solved after the CTF had finished with some help from the challenge author.
I am sharing this as a writeup to help others who like me were curious about the solution to this challenge, yet since so few actually solved it there has been
no solution made public until now.

Since the algorithm as described in the header is ES256, the curve is P-256 (see: https://ldapwiki.com/wiki/ES256). Logging in with different usernames gives a signature with the same prefix,
so there's likely a resuse of k-values. The last 32 bytes of the signature is a SHA256 hash is of the token header and payload.

I recommend you to read https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm#Signature_generation_algorithm,
which details an attack on repeated k-values, and is implemented in this python script. Reading this will give you a better understanding
of this script.

Suprisingly, you didn't have to mess with curves of any kind to solve this challenge, just some basic modular artihmetic, web stuff, and perhaps some research
"""

# curve parameters of P-256 (see: https://ldapwiki.com/wiki/P-256)
n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
L_n = len(bin(n)[2:])

def parse_signature(token):
	t = token.split(".")

	sig = base64.urlsafe_b64decode(t[2]+"===")
	m = t[0]+"."+t[1]

	e = hashlib.sha256(m.encode()).digest()

	z = int(bin(int(e.hex(),16))[2:L_n+2],2)

	r = int(sig[:-32].hex(),16) # start of the signature is r, which is defined as the x-component of the point k*G on the curve
	s = int(sig[-32:].hex(),16) # the last 32 bytes of the signature is the s value
	return r,s,z

# two tokes generated for the usernames "admim" and "admio" respectively
token1 = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJhZG1pbSJ9.wN0kGlDUj5n8x6GGptROB2PskEeOHe-ONvXE6VDWevuMm5QA7M6_aA7V3oa0ohEVhggmzaDWBArvODBI1in4IQ"
token2 = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VybmFtZSI6ICJhZG1pbyJ9.wN0kGlDUj5n8x6GGptROB2PskEeOHe-ONvXE6VDWevucC-db4xgw8VCtuYuKyMUSvvJ7qI8dKwOmWdBDj8dy2g"

# calculate the signature parameters from the tokens
r1, s1, z1 = parse_signature(token1)
r2, s2, z2 = parse_signature(token2)

assert r1==r2 # checks if the r-values match for the two signatures, if they do (spoiler alert: they do), then the same k-value is used and a signature can be forged

# recover the private key d from the two signatures using modular arithmetic (read the wikipedia article)
k = ((z1-z2)*pow((s1-s2)%n,-1,n))%n # k = (z-z')/(s-s') (mod n)
d = ((s1*k-z1)*pow(r1,-1,n))%n

# header and payload of the JWT
admin_token = b"eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9." + base64.urlsafe_b64encode(b'{"username": "admin"}')
admin_token = admin_token.replace(b"=",b"")

# calculate the signature using the recovered private key (again, read the wikipedia article)
e = hashlib.sha256(admin_token).digest() # e = HASH(m)
z = int(bin(int(e.hex(),16))[2:L_n+2],2) # z = e[:L_n] (in bits)
r = r1
s = (pow(k,-1,n)*(z+r*d))%n # s = (z+rd)/k (mod n)

# putting r and s together and encoding
signature = bytes.fromhex(hex(r)[2:]) + bytes.fromhex(hex(s)[2:])
admin_token += b"." + base64.urlsafe_b64encode(signature)

# print forged token
print(admin_token)









