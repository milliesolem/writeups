from pwn import *

def hex2bin(n):
	i = int(n,16) # convert to int
	b = bin(i)[2:] # convert to binary
	l = len(n) # get length
	p = l*4-len(b) # get number of zeros omitted
	b = "0"*p+b # add leading zeros to binary
	return b # return binary

def bin2hex(n):
	i = int(n,2)
	h = hex(i)[2:]
	l = len(n)
	p = l//4-len(h)
	h = "0"*p+h
	return h

def encrypt(p, z, o):
	p = hex2bin(p)
	z = hex2bin(z)
	o = hex2bin(o)
	res = ""
	for i in range(len(p)):
		if p[i] == '0':
			res += z[i]
		else:
			res += o[i]

	return bin2hex(res)


# the encryption is entirely bitwise, so by encrypting two plaintexts, one with all zeros and one with all ones,
# key recovery becomes trivial
# (bitwise means each bit is encrypted individually, there's no mixing going on like with a good cipher like AES)

conn = remote('crypto.2021.chall.actf.co', 21602)

# get zeros
conn.send(b"1\n")
conn.recv()
conn.send(b"0"*64+b"\n")
conn.recv()
zeros = conn.recv().split(b"\n")[0].decode()
print("Zeros:",zeros)

# get ones
conn.send(b"1\n")
conn.recv()
conn.send(b"f"*64+b"\n")
ones = conn.recv().split(b"\n")[0].decode()
print("Ones:",ones)

# encrypt and send
conn.send(b"2\n")
while True:
	c = conn.recv()
	if c[0] == ord("W"):
		print(c.decode())
		conn.close()
		exit()
	ct = c.replace(b'Encrypt this: ',b'').split(b'\n')[0].decode()
	e = encrypt(ct,zeros,ones)
	conn.send(e.encode()+b"\n")















