import os
import zlib
def keystream(i):
	key = bytes([i>>8,i%256])
	index = 0
	while 1:
		index+=1
		if index >= len(key):
			key += zlib.crc32(key).to_bytes(4,'big')
		yield key[index]

with open("enc_","rb") as f:
	plain = f.read()
	for i in range(65536):
		ciphertext = []
		k = keystream(i)
		for i in plain:
			ciphertext.append(i ^ next(k))
		c = bytes(ciphertext)
		if b"actf{" in c:
			print(c)
			exit()
