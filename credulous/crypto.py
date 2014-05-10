from credulous.errors import BadPrivateKey, BadCypherText

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from base64 import b64decode
from getpass import getpass
import paramiko
import logging
import os

log = logging.getLogger("credulous.crypto")

class Crypto(object):
    """Knows how to do crypto"""
    def __init__(self):
        self.keys = {}

    def encrypt(self, message, public_key_loc, **info):
        """Encrypt the specified message using specified public key and return as base64 encoded string"""
        key = open(public_key_loc, "r").read()
        rsakey = RSA.importKey(key)
        rsakey = PKCS1_OAEP.new(rsakey)
        encrypted = rsakey.encrypt(message)
        return encrypted.encode('base64')

    def decrypt(self, package, private_key_loc, **info):
        """Decrypt the specified base64 encoded package using specified private key"""
        key = self.private_key_to_rsa_object(private_key_loc)
        rsakey = PKCS1_OAEP.new(key)

        try:
            decoded = b64decode(package)
        except TypeError:
            raise BadCypherText("Value not valid base64 encoding", **info)

        try:
            return rsakey.decrypt(decoded)
        except ValueError as err:
            raise BadCypherText(err=err, **info)

    def find_key_for_fingerprint(self, fingerprint, default="id_rsa"):
        """Find a private key for this fingerprint or if no fingerprint then default to ~/.ssh/<default>"""
        if fingerprint is None:
            location = os.path.expanduser("~/.ssh/{0}".format(default))

        if not os.path.exists(location):
            raise BadPrivateKey("Couldn't find one to use")

        return location

    def private_key_to_rsa_object(self, location):
        """Get us a RSA object from our private key on disk"""
        if location in self.keys:
            return self.keys[location]

        try:
            key = paramiko.RSAKey.from_private_key_file(location, password=None)
        except paramiko.PasswordRequiredException:
            passphrase = getpass("Password for your private key ({0})\n:".format(location))
            key = paramiko.RSAKey.from_private_key_file(location, password=passphrase )

        key = RSA.construct((key.n, key.e, key.d, key.p, key.q))
        self.keys[location] = key
        return key

