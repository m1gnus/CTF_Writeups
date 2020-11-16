# BabyHash (Crypto)  

### server  

```python
from Crypto.Util.number import getPrime, isPrime, bytes_to_long
from os import urandom
from binascii import unhexlify
from secret import flag

header = """CryptoLog.INC

--------------------------------------------------
Welcome, user!
Please login with valid credentials, checked by our crypto-evoluted system.
--------------------------------------------------


"""

def not_so_funny_check(x, p):
	s = bin(p-1)[::-1].index('1')
	for z in range(2, p):
		if p - 1 == pow(z, (p - 1) // 2, p):
			break
	c = pow(z, (p - 1) // 2 ** s, p)
	r = pow(x, ((p - 1) // 2 ** s + 1) // 2, p)
	t = pow(x, (p - 1) // 2 ** s, p)
	m = s
	t2 = 0
	while (t - 1) // p != (t - 1) / p:
		t2 = (t * t) % p
		i = 0
		for i in range(1, m):
			if (t2 - 1) // p == (t2 - 1) / p:
				break
			t2 = (t2 * t2) % p
		b = pow(c, 1 << (m - i - 1), p)
		r = (r * b) % p
		c = (b * b) % p
		t = (t * c) % p
		m = i
	return r

def funny_check(x, p):
	try:
		not_so_funny_check(x, p)
	except Exception as e:
		return True
	return False

p = 43401284375631863165968499011197727448907264840342630537012422089599453290392542589198227993829403166459913232354777490444915201356560807401141203961578150815557853865678753463969663318864902106651761912058979552119867603661163587639785030788676120329044248495611269533429749805119341551183130515359738240737511058829539566547367223386189286492001611298474857947463007621758421914760578235374029873653721324392107800911728989887542225179963985432894355552676403863014228425990320221892545963512002645771206151750279770286101983884882943294435823971377082846859794746562204984002166172161020302386671098808858635655367

while True:
	x = bytes_to_long(urandom(32))
	x = x % p
	if funny_check(x, p):
		break

while True:
	y = bytes_to_long(urandom(32))
	y = y % p
	if funny_check(y, p):
		break

a = bytes_to_long(b'admin')
b = bytes_to_long(b'password')

server_hash = (pow(x, a, p) * pow(y, b, p)) % p

print(header)

try:
	print('Username:')
	username = input()
	assert len(username) <= 512
	username = unhexlify(username)
	print('Password:')
	password = input()
	assert len(password) <= 512
	password = unhexlify(password)
except:
	print("Input too long! I can't keep in memory such long data")
	exit()

if username == b'admin' or password == b'password':
	print("Intrusion detected! Admins can login only from inside our LAN!")
	exit()

user_hash = (pow(x, bytes_to_long(username), p) * pow(y, bytes_to_long(password), p)) % p

if user_hash == server_hash:
	print("Glad to see you, admin!\n\n")
	print(flag)
else:
	print("Wrong credentials.")
```
### The problem  
let `a` be the integer value corresponding to `b'admin'` and `b` the integer value corresponding to `b'password'`, we know that there are two unknown integers `x` and `y` which will be used to calculate our hash by performing the following operation: `(x^a * y^b) % p`, where `p` is a big prime. We need to find two values `a'` and `b'` such that `(x^a' * y^b') % p` = `(x^a * y^b) % p`
### Unintended solution
the code use `unhexlify` to obtain the bytes, and then it perform the check by using the obtained bytes instad of the corresponding integer values, so we can simply send the hexadecimal string corresponding to `b'\x00admin'` as username and to `b'\x00password'` as password, the integer values corresponding to these two byte strings are the same as the values of `b'admin'` and `b'password'` but the strings itself are different, so we can pass the check and obtain the flag:
```bat
C:\Users\M1gnus>nc challs.ctf.m0lecon.it 8000
CryptoLog.INC

--------------------------------------------------
Welcome, user!
Please login with valid credentials, checked by our crypto-evoluted system.
--------------------------------------------------



Username:
0061646d696e
Password:
0070617373776f7264
Glad to see you, admin!


ptm{a_b1g_s0phi3_germ41n_pr1m3}
```
### Intended solution  
we know that `k^((p-1)/2) % p = -1` if k is a quadratic non residue by the [Euler's criterion](https://en.wikipedia.org/wiki/Euler%27s_criterion), the `funny_check` function returns `True` if `x` is a quadratic non residue modulo `p`, so surely `x` and `y` are quadratic non residue modulo `p`. if we add `(p-1)/2` to both `a` and `b` we obtain the following result (operation done in modulo p): `x^(a + (p-1)/2) * y^(b + (p-1)/2) = x^a * x^((p-1)/2) * y^b * y^((p-1)/2) = x^a * -1 * y^b * -1 = -1 * -1 * x^a * x^b = x^a * x^b`, and we can obtain the flag
```bat
C:\Users\Vittorio>nc challs.ctf.m0lecon.it 8000
CryptoLog.INC

--------------------------------------------------
Welcome, user!
Please login with valid credentials, checked by our crypto-evoluted system.
--------------------------------------------------



Username:
abe6f67efeb8a86949b6c9ce7537e813b428e14a37a043bc7e96d2f31eb424be822daafff5452d34236144e61cdf41eb799a3dbef79bb168d32a9d82b4c5c70ea66a1628d966476d6f5c7652ff81d5d92f97419a0a95499a4f71641203f4eb62bd5ef8d7a2cfcc7252e780cd634c8c429a5e555fb3229bbc08a3d76bf02d37ca36a0544bcbb37f4fdcd9d02bdbaba139ec6cee764d1f880efa491d326ffb4601a688126f86085cb752bda95dffc514944c2cb1bd919d87808bc44088e1017a3da370abe8baea3cd1faae758cb2e0af4671790e9a1621b1928a45825cd19c034e3b8da95e1888fc37c0896e1f49854d4d489ee3891a1c017f70ad18d1556d55d1
Password:
abe6f67efeb8a86949b6c9ce7537e813b428e14a37a043bc7e96d2f31eb424be822daafff5452d34236144e61cdf41eb799a3dbef79bb168d32a9d82b4c5c70ea66a1628d966476d6f5c7652ff81d5d92f97419a0a95499a4f71641203f4eb62bd5ef8d7a2cfcc7252e780cd634c8c429a5e555fb3229bbc08a3d76bf02d37ca36a0544bcbb37f4fdcd9d02bdbaba139ec6cee764d1f880efa491d326ffb4601a688126f86085cb752bda95dffc514944c2cb1bd919d87808bc44088e1017a3da370abe8baea3cd1faae758cb2e0af4671790e9a1621b1928a45825cd19c034e3b8da95e1888fc37c0896e1f49854d4d489ee3891a1c017fe10e8be3686f5ec7
Glad to see you, admin!


ptm{a_b1g_s0phi3_germ41n_pr1m3}
```

# M1gnus ([PGiatasti](https://pgiatasti.it))