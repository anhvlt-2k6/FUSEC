from Crypto.Util.number import bytes_to_long, getPrime

flag = [REDACTED]
m = bytes_to_long(flag)

def encrypt(m):
    e = 65537
    p = getPrime(1024)
    q = getPrime(1024)
    n = p*q
    c = pow(m,e,n)
    a = (p-q)**2
    b = (- a + p**2 + (n/p)**2 )//2
    return e,c,a,b

e,c,a,b = encrypt(m)
print(f"e = {e}")
print(f"c = {c}")
print(f"a = {a}")
print(f"b = {b}")