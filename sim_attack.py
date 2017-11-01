#!/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from pkcs1_breaker import *


_TESTKEY = b"""\
-----BEGIN PRIVATE KEY-----
MIIB5gIBADANBgkqhkiG9w0BAQEFAASCAdAwggHMAgEAAmEAy6bkAC6U7uMOlTZ5
vMr1KTp2J7bYx5UOeW5u2bJxdFpsJZazkW7zywkubN/X1aAkMxA4+L1MzIBDbjMQ
pu26NhzacUCUfqCXXN5KZAXW3pLdu20/axXM0Lzb6lwTxYHTAgMBAAECYQCJQvcx
2DOxv4A4ufrbcMBFBY5VvjvmaWTUG8bDHC60Ca4St7xYLbxMAOg1obnL1p7brF5Z
RYER2ogKXItaNAet/AMgRM3WlaEiO3y856x7DngQlTWeSYgrhFJWXGals6ECMQDm
rQj3LRMGmJ+jaUbk/ddgliUiUroxfgAj9Pthbg0FKIOszJfXaZUN17vIGhLkQocC
MQDiAl4JSKwQh8VU24My0Hahq2wY/Bj3UWuSOnmjxpXKJP766lZ3L9TiMCHPgUjk
/VUCMQDIEy8ijJLi9sAH0UkvVshXOwNsWMqsILhod5UNtZFPdwt2dmIA8c/ZmNOD
xLG8D8MCMEH+0PjDCMN28e9afhAbgViqFtGg46VsWA4GFzj0pw61COO6A++fvvkh
du4B4YhEVQIxANYNTxbxUgqeIm9qcHAUHnakjoYs4a4QfvwSSs4VlFYAuAZDZqu9
UZYeATxPJn8Kjg==
-----END PRIVATE KEY-----
"""

_USAGE = """\
usage:
    {0}
    {0} key message
"""

def load_private_pem(data):
    return serialization.load_pem_private_key(data, password=None, backend=default_backend())

def encrypt_pkcs1(key, msg):
    return key.encrypt(msg, PKCS1v15())

def decrypt_unpadded(key, c):
    d = key.private_numbers().d
    n = key.public_key().public_numbers().n
    m_int = RSADP(n, d, OS2IP(c))
    return I2OSP(m_int, n.bit_length())

def unpad_pkcs1(m):
    for i in range(2, len(m)):
        if m[i] == 0:
            return m[i+1:]


class TestOracle(Oracle):
    def __init__(self, key):
        self.key = key

    def __call__(self, ciphertext):
        padded_msg = decrypt_unpadded(self.key, ciphertext)
        if padded_msg[0] == 0 and padded_msg[1] == 2:
            return Oracle.OK
        else:
            return Oracle.ERROR_PADDING_HEADER


def main():
    if len(sys.argv) == 1:
        key = load_private_pem(_TESTKEY)
        m = "kick it, CC"
    elif len(sys.argv) == 3:
        with open(sys.argv[1], "rb") as f:
            key = load_private_pem(f.read())
        m = sys.argv[2]
    else:
        print(_USAGE.format(sys.argv[0]), file=sys.stderr)
        return

    pubkey = key.public_key()
    nums = pubkey.public_numbers()
    print('Using a {}-bit key and message "{}"'.format(nums.n.bit_length(), m), file=sys.stderr)

    c = encrypt_pkcs1(pubkey, m.encode())

    attack = BB98_Attack(nums.n, nums.e, c, TestOracle(key))
    msg = unpad_pkcs1(attack.find_message())

    print(attack.stats(), file=sys.stderr)
    print("Message was:", msg.decode())


if __name__ == "__main__":
    main()
