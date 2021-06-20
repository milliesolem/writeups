from z3 import *

"""
We're given a set of 9 points on a 3-dimensional multivariate polynomial, as the x and y coordinates of a tenth point,
along with the flag XORed with the z-component of said point. We're essentially taked with recovering the the multivariate
polynomial expression using the 9 points. This can be done by writing the points as a set of equations, then use z3 solver
to recover the expression.
"""

points = [
(26, 66, 70314326037540683861066), (175, 242, 1467209789992686137450970), (216, 202, 1514632596049937965560228), 
(13, 227, 485439858137512552888191), (1, 114, 112952835698501736253972), (190, 122, 874047085530701865939630), 
(135, 12, 230058131262420942645110), (229, 220, 1743661951353629717753164), (193, 81, 704858158272534244116883)
]
a,b = 886191939093, 589140258545
flag = 19440293474977244702108989804811578372332250

# intialize the constants and solver
c = [Int("c"+str(i)) for i in range(6)]
s = Solver()

# we know the constants are 64-bit unsigned integers,
# so we add that constraint to filter down possible solutions
for i in c:
	s.add(i>0)
	s.add(i<2**64)
# set up the points as a set of equations
for p in points:
	x,y,z = p
	s.add(z==c[0]*x**2+c[1]*y**2+c[2]*x*y+c[3]*x+c[4]*y+c[5])

# solve the multivariate polynomial expression
if s.check() == sat:
    m = s.model()
    C = []
    for i in c:
    	print(f"{i} = ",m[i].as_long())
    	C.append(m[i].as_long())
# recover the flag
f = lambda x,y: C[0]*x**2+C[1]*y**2+C[2]*x*y+C[3]*x+C[4]*y+C[5]

solution = f(a,b)
print(bytes.fromhex(hex(f(a,b)^flag)[2:]))