from PIL import Image
from Crypto.Cipher import AES

img = Image.open('flag.png')
assert img.mode == 'RGB'
assert img.height == 250
assert img.width == 2000
assert str([b for rgb in [[1, 2, 3], [4, 5, 6], [7, 8, 9]] for b in rgb]) == '[1, 2, 3, 4, 5, 6, 7, 8, 9]'
data = bytes([b for rgb in img.getdata() for b in rgb])  # flatten
assert len(data) % 16 == 0
key = open('/dev/urandom', 'rb').read(16)
aes = AES.new(key, AES.MODE_ECB)
ct = aes.encrypt(data)
open('flag.png.enc', 'wb').write(ct)
