from credo.errors import BadPrivateKey, BadCypherText, BadFolder, CredoError, BadPlainText

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from base64 import b64decode
from binascii import hexlify
from getpass import getpass
import subprocess
import paramiko
import tempfile
import logging
import shlex
import os

log = logging.getLogger("credo.crypto")

class SSHKeys(object):
    """Stores private and public ssh keys by fingerprint"""
    def __init__(self):
        self.rsa_objs = {}
        self.public_keys = {}
        self.private_keys = {}

    def have_private(self, fingerprint):
        """Says whether we have a private key with this fingerprint"""
        return fingerprint in self.private_keys

    def have_public(self, fingerprint):
        """Says whether we have a public key with this fingerprint"""
        return fingerprint in self.public_keys

    def find_private_keys(self, folder):
        """Find more private keys in specified folder"""
        if not os.path.exists(folder):
            raise BadFolder("Doesn't exist", folder=folder)
        if not os.access(folder, os.R_OK):
            raise BadFolder("Not readable", folder=folder)

        for filename in os.listdir(folder):
            if not filename.endswith(".pub") and filename not in ("known_hosts", "authorized_keys", "config"):
                location = os.path.join(folder, filename)
                if os.access(location, os.R_OK):
                    fingerprint = self.get_fingerprint(location=location)
                    if fingerprint:
                        self.private_keys[fingerprint] = location

    def add_public_keys(self, public_keys):
        """Add the specified public keys"""
        for key in public_keys:
            fingerprint = self.get_fingerprint(key)
            if fingerprint:
                self.public_keys[fingerprint] = key

    def get_fingerprint(self, pem_data=None, location=None):
        """Get a fingerprint from pem_data"""
        tmp = None
        try:
            tmp = tempfile.NamedTemporaryFile(delete=False).name
            if pem_data:
                with open(tmp, 'w') as fle:
                    fle.write(pem_data)
                key_location = tmp
            else:
                key_location = location

            try:
                if location:
                    log.debug("Looking for fingerprint from %s", location)
                result = subprocess.check_output(shlex.split("ssh-keygen -lf {0}".format(key_location)), stderr=open(os.devnull, 'w'))
                fingerprint = result.split(" ")[1]
                log.debug("Found fingerprint!! %s", fingerprint)
                return fingerprint
            except subprocess.CalledProcessError:
                return
        finally:
            if tmp and os.path.exists(tmp):
                os.remove(tmp)

    def private_key_to_rsa_object(self, fingerprint, **info):
        """Get us a RSA object from our private key on disk"""
        if fingerprint in self.rsa_objs:
            return self.rsa_objs[fingerprint]

        if fingerprint not in self.private_keys:
            raise BadPrivateKey("Don't have a private key for specified fingerprint", fingerprint=fingerprint)

        location = self.private_keys[fingerprint]
        log.debug("Using private key at %s (%s) to decrypt (%s)", location, fingerprint, " || ".join("{0}={1}".format(key, val) for key, val in info.items()))

        try:
            key = paramiko.RSAKey.from_private_key_file(location, password=None)
        except paramiko.PasswordRequiredException:
            try:
                passphrase = getpass("Password for your private key ({0})\n:".format(location))
                key = paramiko.RSAKey.from_private_key_file(location, password=passphrase )
            except paramiko.ssh_exception.SSHException as err:
                raise BadPrivateKey("Couldn't decode key, perhaps bad password?", err=err)

        key = RSA.construct((key.n, key.e, key.d, key.p, key.q))
        self.rsa_objs[fingerprint] = key
        return key

    def encrypt(self, message, fingerprint, **info):
        """Encrypt the specified message using specified public key and return as base64 encoded string"""
        log.debug("Using public key with fingerprint %s to encrypt (%s)", fingerprint, " || ".join("{0}={1}".format(key, val) for key, val in info.items()))
        rsakey = RSA.importKey(self.public_key_pem(fingerprint))
        rsakey = PKCS1_OAEP.new(rsakey)
        try:
            encrypted = rsakey.encrypt(message)
        except ValueError as err:
            raise BadPlainText(error=err, **info)
        return encrypted.encode('base64')

    def decrypt(self, package, fingerprint, **info):
        """Decrypt the specified base64 encoded package using specified private key"""
        key = self.private_key_to_rsa_object(fingerprint, **info)
        rsakey = PKCS1_OAEP.new(key)

        try:
            decoded = b64decode(package)
        except TypeError:
            raise BadCypherText("Value not valid base64 encoding", **info)

        try:
            return rsakey.decrypt(decoded)
        except ValueError as err:
            raise BadCypherText(err=err, **info)

    def public_key_pem(self, fingerprint):
        """Return the PEM encoding of the public key for this fingerprint"""
        return self.public_keys[fingerprint]

    def private_key_pem(self, fingerprint):
        """Return the PEM encoding of the private key for this fingerprint"""
        return open(self.private_keys[fingerprint]).read()

class Crypto(object):
    """Knows how to do crypto"""
    def __init__(self, keys=None):
        if keys is None:
            keys = SSHKeys()
        self.keys = keys

    def find_private_keys_in(self, folder):
        """Find keys to add"""
        self.keys.find_private_keys(folder)

    def add_public_keys(self, public_keys):
        """Add public keys"""
        self.keys.add_public_keys(public_keys)

    def has_public_keys(self):
        """Say True if we have any public keys"""
        return len(self.keys.public_keys) > 0

    def decryptable(self, fingerprints):
        """Say whether we have a private key for any of these fingerprints"""
        return any(self.keys.have_private(fingerprint) for fingerprint in fingerprints)

    def decrypt_by_fingerprint(self, fingerprints, verifier_maker, **info):
        """Yield each different decrypted value if we find any and check against the verifier"""
        found = set()
        for fingerprint, values in fingerprints.items():
            if self.keys.have_private(fingerprint):
                decrypted = {}
                for key, val in values.items():
                    info = dict(info)
                    info["key"] = key
                    info["key_fingerprint"] = fingerprint
                    info["action"] = "decrypting"
                    decrypted[key] = self.keys.decrypt(val, fingerprint, **info)

                new_verifier = verifier_maker(values, decrypted)
                if not decrypted["__account_verifier__"] == new_verifier:
                    log.error("Ignoring decrypted secrets, because verifier doesn't match: %s", " || ".join("{0}={1}".format(key, val) for key, val in info.items()))
                else:
                    decrypted["__account_verifier__"] = new_verifier
                    identity = ",".join(sorted(str((key, val) for key, val in decrypted.items() if not key.startswith("_"))))
                    if identity not in found:
                        found.add(identity)
                        yield decrypted

    def fingerprinted(self, decrypted_vals, verifier_maker, **info):
        """
        Return dictionary of {<fingerprint>: <info>}

        Where <info> is unencrypted keys to encrypted values
        With a __account_verifier__ key
        """
        if not isinstance(decrypted_vals, dict):
            raise CredoError("Fingerprinted should only be called with dictionaries", got_type=type(decrypted_vals))

        result = {}
        for fingerprint in self.keys.public_keys:
            encrypted = {}
            for key, val in decrypted_vals.items():
                info = dict(info)
                info["key_fingerprint"] = fingerprint
                info["action"] = "encrypting"
                info["key"] = key
                encrypted[key] = self.keys.encrypt(val, fingerprint, **info)

            info["key"] = "__account_verifier__"
            encrypted["__account_verifier__"] = self.keys.encrypt(verifier_maker(encrypted, decrypted_vals), fingerprint, **info)
            result[fingerprint] = encrypted

        return result

