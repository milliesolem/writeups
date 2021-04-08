import random
import secrets
import math
from decimal import Decimal, getcontext
from Cryptodome.Cipher import AES
"""
The secret to this challenge is to realize that what we're given are points on a circle,
with the offset on the x axis being the key and the offset on the y axis is the iv.
The solution is found by Googling "find circle with 3 points" and copy-pasing the equations from a random website.
"""

getcontext().prec = 50

ct = "838371cd89ad72662eea41f79cb481c9bb5d6fa33a6808ce954441a2990261decadf3c62221d4df514841e18c0b47a76"

x1, y1 = (Decimal("45702021340126875800050711292004769456.2582161398"), Decimal("310206344424042763368205389299416142157.00357571144"))
x2, y2 = (Decimal("55221733168602409780894163074078708423.359152279"), Decimal("347884965613808962474866448418347671739.70270575362"))
x3, y3 = (Decimal("14782966793385517905459300160069667177.5906950984"), Decimal("340240003941651543345074540559426291101.69490484699"))


# Source: http://www.ambrsoft.com/TrigoCalc/Circle3D.htm
A = x1*(y2 - y3) - y1*(x2 - x3) + x2*y3 - x3*y2
B = (x1**2 + y1**2)*(y3 - y2) + (x2**2 + y2**2)*(y1 - y3) + (x3**2 + y3**2)*(y2 - y1)
C = (x1**2 + y1**2)*(x2 - x3) + (x2**2 + y2**2)*(x3 - x1) + (x3**2 + y3**2)*(x1 - x2)
D = (x1**2 + y1**2)*(x3*y2 - x2*y3) + (x2**2 + y2**2)*(x1*y3 - x3*y1) + (x3**2 + y3**2)*(x2*y1 - x1*y2)

# The center of the circle is the key and iv
keynum = int(round(-B/(2*A)))
ivnum = int(round(-C/(2*A)))

key = int.to_bytes(keynum, 16, "big")
iv = int.to_bytes(ivnum, 16, "big")

cipher = AES.new(key, AES.MODE_CBC, iv=iv)
enc = cipher.decrypt(bytes.fromhex(ct))
print(enc)













