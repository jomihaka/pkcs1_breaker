#!/usr/bin/env python3

import argparse
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

def load_private_pem(data):
    return serialization.load_pem_private_key(data, password=None, backend=default_backend())

def encrypt_pkcs1(key, msg):
    return key.encrypt(msg, PKCS1v15())

def encrypt_unpadded(key, m):
    n = key.public_numbers().n
    e = key.public_numbers().e
    c_int = RSAEP(n, e, OS2IP(m))
    return I2OSP(c_int, n.bit_length())

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
    parser = argparse.ArgumentParser(
        description='Simulates the PKCS#1v15 padding attack'
    )
    parser.add_argument(
        '-k', '--key',
        help='PEM formatted file containing a private key to use with oracle'
    )
    parser.add_argument(
        '--unpadded',
        action='store_true',
        help='Message is not padded before encrypting (this tests steps 1 and 4)'
    )
    parser.add_argument(
        'm',
        metavar='message',
        nargs='?',
        default='kick it, CC',
        help='Message to use'
    )

    args = parser.parse_args()

    if args.key:
        with open(args.key, "rb") as f:
            key = load_private_pem(f.read())
    else:
        key = load_private_pem(_TESTKEY)

    m = args.m

    pubkey = key.public_key()
    nums = pubkey.public_numbers()
    print('Using a {}-bit key and message "{}"'.format(nums.n.bit_length(), m), file=sys.stderr)

    if args.unpadded:
        c = encrypt_unpadded(pubkey, m.encode())
    else:
        c = encrypt_pkcs1(pubkey, m.encode())

    attack = BB98_Attack(nums.n, nums.e, c, TestOracle(key))
    msg = unpad_pkcs1(attack.find_message())

    print(attack.stats(), file=sys.stderr)
    print("Message was:", msg.decode())


if __name__ == "__main__":
    main()
