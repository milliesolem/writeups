from sage.all import *
from pwn import *

# python doesn't have built-in product function for some reason :P
def product(n):
	res = 1
	for i in n:
		res *= i
	return res

# RNG from chal
class Generator():
    DIGITS = 8
    def __init__(self, seed):
        self.seed = seed
        #assert(len(str(self.seed)) == self.DIGITS)

    def getNum(self):
        self.seed = int(str(self.seed**2).rjust(self.DIGITS*2, "0")[self.DIGITS//2:self.DIGITS + self.DIGITS//2])
        return self.seed

# Crack RNG from chal
class CrackRNG:
	def __init__(self,number):
		f = list(factor(number))
		d = []
		for i in f:
			for j in range(i[1]):
				d.append(i[0])
		self.possible_seeds = [] # list of all groups of seeds that could produce initial number
		for i in range(2**len(d)):
			self.possible_seeds.append(self.getGroup(d,i))
	# generate the nth pair of numbers whose product is the initial number
	def getGroup(self,d,n):
		b = bin(n)[2:][::-1]
		b += '0'*(len(d)-len(b)) # pad the binary
		l1 = []
		l2 = []
		for i,j in zip(b,d):
			if i=='1':
				l1.append(j)
			else:
				l2.append(j)
		return product(l1),product(l2)
	# filter out possible seeds that don't produce the same number
	def feed(self,number):
		new_cands = []
		for i in self.possible_seeds:
			r1, r2 = i
			g1, g2 = Generator(r1), Generator(r2)
			n1, n2 = g1.getNum(), g2.getNum()
			if n1*n2 == number:
				new_cands.append((n1,n2))
		self.possible_seeds = new_cands
	# returns a list of all potential next numbers based on the possible internal states
	def getNextNumber(self):
		nn = []
		for i in self.possible_seeds:
			r1,r2 = Generator(i[0]), Generator(i[1])
			nn.append(r1.getNum()*r2.getNum())
		return nn

conn = remote('crypto.2021.chall.actf.co', 21600)
conn.recv()
conn.send(b'r\n')

# Only two numbers are needed to filter down the possible internal states to one
c1 = int(conn.recv().decode().split("\n")[0])
conn.send(b'r\n')
c2 = int(conn.recv().decode().split("\n")[0])

cr = CrackRNG(c1)
cr.feed(c2)

# Get the next two numbers
c3 = str(cr.getNextNumber()[0]).encode()
cr.feed(cr.getNextNumber()[0])
c4 = str(cr.getNextNumber()[0]).encode()

# Get da flag!
conn.send(b'g\n')
(conn.recv())
conn.send(c3+b'\n')
(conn.recv())
conn.send(c4+b'\n')
print(conn.recv().decode())
conn.close()
