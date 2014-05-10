from credulous.errors import BadPrivateKey, BadCypherText

from Crypto.Util.py3compat import tobytes, b
from Crypto.Cipher import DES, DES3, AES
from Crypto.Protocol.KDF import PBKDF1
from Crypto.Util.Padding import unpad
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util import asn1
from Crypto.Hash import MD5
import Crypto

from binascii import unhexlify, a2b_base64
from base64 import b64decode
from getpass import getpass
import os

def encrypt(message, public_key_loc, **info):
    """Encrypt the specified message using specified public key and return as base64 encoded string"""
    key = open(public_key_loc, "r").read()
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    encrypted = rsakey.encrypt(message)
    return encrypted.encode('base64')

def decrypt(package, private_key_loc, **info):
    """Decrypt the specified base64 encoded package using specified private key"""
    key = private_key_to_rsa_object(private_key_loc)
    rsakey = PKCS1_OAEP.new(key)

    try:
        decoded = b64decode(package)
    except TypeError:
        raise BadCypherText("Value not valid base64 encoding", **info)

    try:
        return rsakey.decrypt(decoded)
    except ValueError as err:
        raise BadCypherText(err=err, **info)

def find_key_for_fingerprint(fingerprint, default="id_rsa"):
    """Find a private key for this fingerprint or if no fingerprint then default to ~/.ssh/<default>"""
    if fingerprint is None:
        location = os.path.expanduser("~/.ssh/{0}".format(default))

    if not os.path.exists(location):
        raise BadPrivateKey("Couldn't find one to use")

    return location

def private_key_to_rsa_object(location):
    """Get us a RSA object from our private key on disk"""
    key = open(location, "r").read().strip()
    lines = key.replace(' ', '').split('\n')[1:-1]

    key_lines = None
    info_lines = []
    for line in lines:
        if key_lines is not None:
            key_lines.append(line)
        else:
            if line == "":
                key_lines = []
            else:
                info_lines.append(line)

    if key_lines is None:
        key_lines, info_lines = info_lines, []

    if info_lines:
        # First we must decrypt!
        objdec = decrypt_key(info_lines, key_lines, location)
        data = a2b_base64(b(''.join(key_lines)))
        try:
            key = unpad(objdec.decrypt(data), objdec.block_size)
        except Crypto.Util.Padding.PaddingError as err:
            raise BadPrivateKey("Couldn't decrypt, perhaps bad password?", err=err)

        seq = asn1.DerSequence()
        seq.decode(key)
        return RSA.construct( (seq[0], seq[1]) )

    try:
        return RSA.importKey(key)
    except ValueError as err:
        raise BadPrivateKey("Couldn't import", error=err, location=location)

def decrypt_key(info_lines, key_lines, location):
    """Decrypt the password protected key"""
    if len(info_lines) != 2:
        raise BadPrivateKey("Unknown password protection, expected two metadata lines", location=location)

    # THe following is from master branch of pycrypto
    # This may be removed when it's released as part of pycrypto
    DEK = info_lines[1].split(':')
    if len(DEK) != 2 or DEK[0] != 'DEK-Info':
        raise BadPrivateKey("PEM encryption format not supported")

    # Method for getting the passphrase
    passphrase = lambda: getpass("Password for your private key ({0})\n:".format(location))

    # Determine our algorithm and salt
    algo, salt = DEK[1].split(',')
    salt = unhexlify(tobytes(salt))

    if algo == "DES-CBC":
        # This is EVP_BytesToKey in OpenSSL
        key = PBKDF1(passphrase(), salt, 8, 1, MD5)
        objdec = DES.new(key, DES.MODE_CBC, salt)
    elif algo == "DES-EDE3-CBC":
        # Note that EVP_BytesToKey is note exactly the same as PBKDF1
        key = PBKDF1(passphrase(), salt, 16, 1, MD5)
        key += PBKDF1(key + passphrase, salt, 8, 1, MD5)
        objdec = DES3.new(key, DES3.MODE_CBC, salt)
    elif algo == "AES-128-CBC":
        key = PBKDF1(passphrase(), salt[:8], 16, 1, MD5)
        objdec = AES.new(key, AES.MODE_CBC, salt)
    else:
        raise BadPrivateKey("Unsupport PEM encryption algorithm", algorithm=algo)

    return objdec

