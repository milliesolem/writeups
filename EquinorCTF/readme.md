# Equinor CTF 2021 Writeup

Heres a small writeup on the Crypto challenges for Equinor CTF 2021

## Really Solid Algebra

We are given the code:

```py
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
```

Along with the modulus and some ciphertext:

```
13170168669036673658789415835821860466913191064101534501779274940690742604281448647173671946400157617199838272310601920602142822774113607705996734952326957290215951537099625639427739047605224303952391610020730760816940205220160216771511419133822833718461981026872830323755731912443015969055035169814519489784526129811052288823469079931979611710076056973923037676007513769049838507897490490814829478688852449121000733730837518239278607078752774705826529888903312298568894804438251828413144707077871047124974876546688478973141243880671642440976847597210524941636796956020071417167383875898209056473829391281999028768027
b'$\x1f\xcd\x00=\xd8\xe7"w\x92\xf4\xd4_D\xe4\xba\x0be\xc3\x07\xd9/;\xcf\x0eD\xe4UE\xcb\x81\xfb\xd8\xe7\x98\x02\xa1w\xc9#\x84\xcf\x10V\xf6\x8aZ\xad\xee\x1a+Z\xb3Kp\xd3]1\x0f\xb9\x16l\xa6R\xa0uK\x13\xbebtY\xe3Y\xdan\x99\x8d5}\xbai\xd2ss&\xb4h:U\xe4\xf8\x08\xfc)\xfeP\x0c\xa8tq\xd0Y\xd1\x81\xd5\xa2P\xcf\xcd\xee\xb9X<1\xaa\x0f\xcb\x89\x88\x15\xabj\xfc\xec\x05:\xc11\xf3\xc5\xb4"\xa5\x03jy\x9f\x8c\xa0r\xb8\xbcu\x07\xda\xa3\xebt\\w\xa7\xc4x\xe6G\xf3\xc3\x84\xc0U22\xa3a\x80S\x7f\x18>\x04}\xe9\xcd\x97\xe6\x8e\xf8\xf5\x03\x88\x97\xab\x1b\x1b\x1f\xbe7\'\x90P\xbc\'\x02 \xf2.\x18\xce\x89ua\xf6#3PU\xb3\xe5x\xfd\xbd\xf0\x86\xd8\x17U\xd2m\xf8!\xc7\x99e\x12\xdb\xeb\x86\xf4\x14\x833>\xc0\xa2\xdck\x94\xd3\xbc\x05-\xcc\xb6 \x96\xc4C\x1a&\xaf\xcb\xb8.\xcep'
```

RSA is an asymmetric cryptosystem that relies on the hardness of factoring numbers whose factors are big and randomly selected, compared to the relative ease of multiplication. In the RSA cryptosystem, you pick two prime numbers `p` and `q` and multiply them together to get the "modulus" `n`, knowing `p` and`q` makes it easy to derive `n`, but only knowing `n` makes it close to impossible to find `p`, and `q`, provided they are random and prime.

The problem in this case is that `q` is selected to be the prime number right after `p`. While factoring is hard, calculating a square root is not, and since the numbers are relatively close together, you can essentially compute it like a square root. French Mathematician Pierre de Fermat realized as much in the 1600s, and inveted a special algorithm that could quickly factor numbers whose prime factors were close together simply by computing the square root then guessing a distance from the square root. Since the prime factors are close, they should be approximately equal to the square root and thus be easily found using this method.

[Wikipedia](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method) provides pseudocode of such an algorithm:

```
FermatFactor(N): // N should be odd
    a ← ceiling(sqrt(N))
    b2 ← a*a - N
    repeat until b2 is a square:
        a ← a + 1
        b2 ← a*a - N 
     // equivalently: 
     // b2 ← b2 + 2*a + 1 
     // a ← a + 1
    return a - sqrt(b2) // or a + sqrt(b2)
```

and here's the python version of the same algorithm:

```py
from gmpy2 import iroot
def FermatFactor(N):
    a = int(iroot(N,2)[0])+1
    b2 = a*a - N
    while not iroot(b2,2)[1]:
        a = a + 1
        b2 = a*a - N 
    b = int(iroot(b2,2)[0])
    return (a - b, a + b)
```

Using this method, we quicky figure out the factors of the modulus:
```
13170168669036673658789415835821860466913191064101534501779274940690742604281448647173671946400157617199838272310601920602142822774113607705996734952326957290215951537099625639427739047605224303952391610020730760816940205220160216771511419133822833718461981026872830323755731912443015969055035169814519489784526129811052288823469079931979611710076056973923037676007513769049838507897490490814829478688852449121000733730837518239278607078752774705826529888903312298568894804438251828413144707077871047124974876546688478973141243880671642440976847597210524941636796956020071417167383875898209056473829391281999028768027 = 114761355294527058224622861107606630879034830600188669071381672438274915604836363270006073038488687244873202683844990751830702476759188657682705934187203554885828875215187956457004941023073622353514828385218517280681450849554176816689299473448025493234673090587933642765556764040289982864680558211516240541749 * 114761355294527058224622861107606630879034830600188669071381672438274915604836363270006073038488687244873202683844990751830702476759188657682705934187203554885828875215187956457004941023073622353514828385218517280681450849554176816689299473448025493234673090587933642765556764040289982864680558211516240542223
```

Next we simply have to calculate the private key and decrypt the ciphertext:

```py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from gmpy2 import iroot

def FermatFactor(N):
    a = int(iroot(N,2)[0])+1
    b2 = a*a - N
    while not iroot(b2,2)[1]:
        a = a + 1
        b2 = a*a - N 
    b = int(iroot(b2,2)[0])
    return (a - b, a + b)

N = 13170168669036673658789415835821860466913191064101534501779274940690742604281448647173671946400157617199838272310601920602142822774113607705996734952326957290215951537099625639427739047605224303952391610020730760816940205220160216771511419133822833718461981026872830323755731912443015969055035169814519489784526129811052288823469079931979611710076056973923037676007513769049838507897490490814829478688852449121000733730837518239278607078752774705826529888903312298568894804438251828413144707077871047124974876546688478973141243880671642440976847597210524941636796956020071417167383875898209056473829391281999028768027

p,q = FermatFactor(N)
phi = (p-1)*(q-1)
e = 65537
d = pow(e,-1,phi)

ciphertext = b'$\x1f\xcd\x00=\xd8\xe7"w\x92\xf4\xd4_D\xe4\xba\x0be\xc3\x07\xd9/;\xcf\x0eD\xe4UE\xcb\x81\xfb\xd8\xe7\x98\x02\xa1w\xc9#\x84\xcf\x10V\xf6\x8aZ\xad\xee\x1a+Z\xb3Kp\xd3]1\x0f\xb9\x16l\xa6R\xa0uK\x13\xbebtY\xe3Y\xdan\x99\x8d5}\xbai\xd2ss&\xb4h:U\xe4\xf8\x08\xfc)\xfeP\x0c\xa8tq\xd0Y\xd1\x81\xd5\xa2P\xcf\xcd\xee\xb9X<1\xaa\x0f\xcb\x89\x88\x15\xabj\xfc\xec\x05:\xc11\xf3\xc5\xb4"\xa5\x03jy\x9f\x8c\xa0r\xb8\xbcu\x07\xda\xa3\xebt\\w\xa7\xc4x\xe6G\xf3\xc3\x84\xc0U22\xa3a\x80S\x7f\x18>\x04}\xe9\xcd\x97\xe6\x8e\xf8\xf5\x03\x88\x97\xab\x1b\x1b\x1f\xbe7\'\x90P\xbc\'\x02 \xf2.\x18\xce\x89ua\xf6#3PU\xb3\xe5x\xfd\xbd\xf0\x86\xd8\x17U\xd2m\xf8!\xc7\x99e\x12\xdb\xeb\x86\xf4\x14\x833>\xc0\xa2\xdck\x94\xd3\xbc\x05-\xcc\xb6 \x96\xc4C\x1a&\xaf\xcb\xb8.\xcep'


key = RSA.construct((N, e, d, p, q))
rsa = PKCS1_OAEP.new(key)

print(rsa.decrypt(ciphertext))
```

Which gives ut the flag: `EPT{5qrt_b3_sc4ry_owo}`


## Arbitrary Encoding System

This challenge exemplifies exactly why modes of operations are important. We are given an encrypted file and a python script. The python script takes an image, extracts the pixels to an array of 1-byte values, then encrypts it using ECB-mode encyption. ECB-mode is the simplest mode of operation; it simply splits the message into blocks, encrypts each one individually, then appends the results together. No XOR-ing, no IVs, nothing.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/d/d6/ECB_encryption.svg/601px-ECB_encryption.svg.png)

The reason why this is a problem is that encrypting the same plaintext twice will result in the same block of ciphertext. This becomes a problem when you have a lot of repeating ciphertext like in an image. All the white pixels will encrypt to some other color and the black pixels to another color. So simply parsing the ciphertext as an image will give you the flag:

```py
from PIL import Image

img = Image.new( 'RGB', (250,2000), "black") # create a new black image
pixels = img.load() # create the pixel map
with open('flag.png.enc','rb') as f:
	ct = f.read()
print("Loading image...")
for i in range(img.size[0]):    # for every col:
    for j in range(img.size[1]):    # For every row
        pixels[i,j] = tuple([a for a in ct[:3]])
        ct = ct[3:]
print("Saving image...")

img.save("ept_flag.png")
```

The resulting image clearly reads `EPT{mode_of_operation_is_important}`

## forge your way in

We are given a link to a website along with the Flask-app source code behind it. Again they make the mistake of using ECB mode of encryption. This time they encrypt the session cookie, which contains the undername, current time, and a flag of whether the user is admin.

```py
def get_auth_cookie(username, admin=False):
    if "&" in username or "=" in username:
        abort(BAD_REQUEST)
    user_is_admin = 1 if admin else 0
    return hexlify(encrypt_auth_cookie(f"username={username}&current_time={str(int(time.time()))}&user_is_admin={user_is_admin}"))
```
So a user with username `example` would get the cookie `username=example_user&current_time=1635687041&user_is_admin=0`

Fortunately for us, the admin flag is put at the very end of the cookie, and we may give an arbitrarily long username, meaning we can cut it off exactly at the character before the `0` at the end. In addition, since our username can be arbirarily long, we can in essence encrypt our own blocks. As long as `user_is_admin` is set to something other than `0`, it will be interpreted as true (this is how it works in most programming languages), and using our ability to encrypt arbitrary blocks, we can do exactly that.

So we have our attack, what's next? We start by observing that `username=` is 9 bytes long. AES encrypts blocks of 16 bytes, so by adding another 7 bytes and add 16 bytes for our custom block, we make a username consisting of 23 bytes: `11111111111111111111111`

We try to log in with this and get the cookie (adding new lines per block to make it easy to read):

```
422ba85895a84fec70c42b6f0d237c91
60e135574fa1d32871216c36589c3ea8
f06020672ef237226ab090d77c247f0b
e722b6063e10291c2f6813cd349fbbd7
6182617f3600d672adf3eea7ae011f09
```

We know the second block `60e135574fa1d32871216c36589c3ea8` is only 1s, so we put it to the side and move on to the next task: cutting off at the last `0`. We do this by measing the length of `username=example_user&current_time=1635687041&user_is_admin=` (cookie with no username and cutting off `0`) to be 48. Exactly divisible by the block size. So our new user should have a username exactly the length of the block size (16 bytes). So I make the user `AAAAAAAAAAAAAAAA` and look at its cookie:

```
20ab1aa5894862ea07784ba8b123f1c2
018c91220ca027e4d79af5b01de653df
74dcefee2cd1966b6a2904398c809b24
825a19b11693f6b7ff207fad93c0c78e
3591561ad0fcd9fdda4835a669c2862e
```

Now we can take the block of 1s from earlier and paste it in before the last block (which is just the 0 and some padding, which we don't care about) to get this cookie:


```
20ab1aa5894862ea07784ba8b123f1c2
018c91220ca027e4d79af5b01de653df
74dcefee2cd1966b6a2904398c809b24
825a19b11693f6b7ff207fad93c0c78e
60e135574fa1d32871216c36589c3ea8
3591561ad0fcd9fdda4835a669c2862e
```
Using this cookie and going to `/flag` gives us the flag:

`EPT{that_w4s_t00_ez}`

## 🔥 Sessions are key! 🔥

We're given a website and its source code. Visiting the website, we may log in as a demo user. Doing this sets a cookie `session` to be the base64-encoded version of the following JSON:

```json
{"user_level": "MA==", "username": "ZGVtbw==", "signature": "1ea11466d214cf5fb292e8d3bf93f5f6"}
```


Looking at the source code we're given, we see that the signature is generated by appending the other attributes of the cookie to the secret signing key and calculating the MD5-digest:

```python
def bytes_to_sign(cookie):
    return key.encode() + b"".join([x.encode()+b64decode(y) for x,y in sorted(cookie.items())])

def sign_session_cookie(cookie):
    return hashlib.md5(bytes_to_sign(cookie)).hexdigest()

```

Since MD5 is a Merkle-Damgård construction, this is potentially vulnerable to signature forgery using a [length-extention attack](https://en.wikipedia.org/wiki/Length_extension_attack). It might be easier to understand by looking at a diagram of a Merkle-Damgård type construction:

![](https://upload.wikimedia.org/wikipedia/commons/e/ed/Merkle-Damgard_hash_big.svg)

Hash functions that base themselves om Merkle-Damgård constructions (MD5, SHA-family, etc.) will start with an initial internal state (IV), then split the message that is to be hashed into blocks, then update the internal state with each block. When all blocks have been processed, the internal state is given as the digest. The problem with this in our case is that since the key is appended at the front, we don't really need the key to make our own signatures. The signature we're given is literally the internal state after processing the last block, and we can simply use this as our IV and add whatever we want at the end. This is what length-extention attacks is all about.

Now we should take a look at what actually gets signed, by setting a key and running the above code:

```
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXuser_level0usernamedemo
```

We don't know the key (marked with `X`), but we do know that it ends with `user_level0usernamedemo` and that the internal state that gets outputted is `1ea11466d214cf5fb292e8d3bf93f5f6`. One problem here is that we want to change `user_level` in the JSON, but since the parameters gets sorted, the username field will get placed after it, which at first glance seems to foil our evil plans of using length extention; however, there is a neat trick we can use to get around this. Simply by adding a new attribute `user` to the cookie, we can set its value to be `_level0usernamedemo` (plus whatever padding generated from the hash function), and the signature will still be the same. Now we can theoretically using length extention make any signature with any attribute we want!

We could of course mess about with padding and internal states to perform the attack, but luckily someone as already done that work for us, and there's this wonderful tool [HashPump](https://github.com/bwall/HashPump) that does exactly what we want with a single command...

```sh
$ hashpump -s '1ea11466d214cf5fb292e8d3bf93f5f6' --data 'user_level0usernamedemo' -a 'user_level1usernamedemo' -k 56
139d3f6b2443bb14765ae93d691ac49f
user_level0usernamedemo\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x02\x00\x00\x00\x00\x00\x00user_level1usernamedemo
```
Awesome! Now we can use this to make our forged session cookie by using our trick from eariler by putting the original signature plaintext and padding under its own "user" parameter. Our forged cookie is:

```
{"user":"X2xldmVsMHVzZXJuYW1lZGVtb4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeAIAAAAAAAA=","user_level": "MQ==", "username": "ZGVtbw==", "signature": "139d3f6b2443bb14765ae93d691ac49f"}
```

Base64-encoding this and setting that as our cookie gives us access to the admin dashboard, where the flag waits for us:

`EPT{h0m3m4d3-crypto-n0-g00d}`


## Thoughts

Equinor really delivered on this one. These challenges were really fun and I had a blast playing this CTF. I really look forward to what they have in store next.