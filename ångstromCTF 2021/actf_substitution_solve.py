
from pwn import *
from sage.all import *

"""
Lagrange interpolation allows us to take a set of n points (even over a finite field), and produce
the polynomial of degree n-1 that passes through those points (yes, there's only one polynomial with that propety for any set given of n points).
In this challenge, we're allowed to send a number to the server, and in return it will plug that number into a polynomial
where each coefficient is a character in the flag (modulo 691), and give us back the result.
By sending the server all numbers from 0 to 50 (or however long we think the flag is), we get enough points
to reconstruct the polynomial using lagrange interpolation, and can thus recover the flag.

If that's too mathy for you, just imagine drawing a line through two points, notice how that's the only unique line that can pass
through any set of two points. A linear equation is a polynomial of degree 1, and it takes 2 points to decide any such polynomial.
The same rings true for all polynomials of degree n, you will need a set of n+1 points to decide which polynomial it is.
"""

def getFlag(p):
	F = GF(691)
	R = F['x']
	pol = R.lagrange_polynomial(p)
	return "".join([chr(int(i)%256) for i in pol.list()])
points = []
conn = remote('crypto.2021.chall.actf.co', 21601)

conn.recv()

# 50 points should be enough to get the flag
for x in range(50):
	conn.send(str(x).encode()+b'\n')
	y = int(conn.recv().split(b'\n')[0][3:])
	points.append((x,y))

# Bruteforce the length of the flag
for i in range(len(points)):
	flag = getFlag(points[:i])[::-1].encode()
	if b'actf{' in flag:
		print(flag)
		break

conn.close()










