import hashlib
from Crypto.Cipher import DES, ARC4

def f():
    m1 = hashlib.md5(b"data")
    m2 = hashlib.new("sha1", b"data")
    c1 = DES.new(b"12345678")
    c2 = ARC4.new(b"secretkey")
    return m1.hexdigest(), m2.hexdigest(), c1, c2

if __name__ == "__main__":
    print(f())
