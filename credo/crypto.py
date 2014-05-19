from credo.errors import (
      BadSSHKey, BadCypherText, BadFolder, CredoError
    , BadPlainText, PasswordRequired, BadPrivateKey, BadPublicKey
    )
from credo.asker import ask_for_choice

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from base64 import b64decode
from binascii import hexlify
from paramiko import Message
from getpass import getpass
import tempfile
import paramiko
import logging
import os
import re

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
                    try:
                        fingerprint = self.make_fingerprint(self.rsaobj_from_location(location, only_need_public=True))
                        if fingerprint:
                            self.private_keys[fingerprint] = location
                    except BadSSHKey:
                        pass

    def make_fingerprint(self, rsa_obj):
        """Get us a fingerprint from this rsa_obj"""
        string = hexlify(rsa_obj.get_fingerprint())
        return ":".join(re.findall("..", string))

    def add_public_keys(self, public_keys):
        """Add the specified public keys"""
        for key in public_keys:
            try:
                fingerprint = self.make_fingerprint(self.rsaobj_from_pem(key))
                self.public_keys[fingerprint] = key
            except BadSSHKey:
                pass

    def rsaobj_from_location(self, location, only_need_public=False):
        """
        Get us a fingerprint from this location

        If the location is a password protected private key, then we look for a public key
        If we can't find a public key, then we ask for the password and get the fingerprint that way

        If it isn't a private key, then we raise a credo.NotSSHKey exception
        """
        try:
            obj = self.make_rsaobj(location, private=True)
            return obj
        except PasswordRequired:
            if only_need_public:
                pub_key = "{0}.pub".format(location)
                if os.path.exists(pub_key):
                    try:
                        return self.make_rsaobj(pub_key)
                    except BadSSHKey as err:
                        log.info("Something wrong with public key %s: %s", pub_key, err)
                        raise

        while True:
            if only_need_public:
                log.info("Couldn't find a public key for password protected private key at %s", location)

            password = self.get_password(location)
            try:
                obj = self.make_rsaobj(location, password=password, private=True)
                return obj
            except BadSSHKey:
                choice = ask_for_choice("Couldn't decode the key ({0})", ["Try again", "Ignore"])
                if choice == "Ignore":
                    return

    def rsaobj_from_pem(self, pem_data):
        """Get us a fingerprint from a public key pem_data."""
        tmp = None
        try:
            tmp = tempfile.NamedTemporaryFile(delete=True).name
            with open(tmp, 'w') as fle:
                fle.write(pem_data)
            return self.make_rsaobj(tmp)
        finally:
            if tmp and os.path.exists(tmp):
                os.remove(tmp)

    def make_rsaobj(self, location, password=None, private=False):
        """Get us an rsa object for this location"""
        try:
            if private:
                return paramiko.RSAKey.from_private_key_file(location, password=password)
            else:
                txt = open(location).read()
                if not txt.startswith("ssh-rsa"):
                    raise BadPublicKey("Doesn't start with ssh-rsa")
                split = txt.split(" ")
                if len(split) < 2:
                    raise BadPublicKey("Expecting more")

                try:
                    der = b64decode(split[1])
                except TypeError:
                    raise BadPublicKey("Couldn't decode")

                return paramiko.RSAKey(msg=Message(der))
        except paramiko.PasswordRequiredException:
            raise PasswordRequired()
        except paramiko.ssh_exception.SSHException as err:
            raise BadSSHKey("Couldn't decode key, perhaps bad password?", err=err)

    def get_password(self, source):
        """Ask user for a password"""
        return getpass("Password for your private key ({0})\n:".format(source))

    def private_key_to_rsa_object(self, fingerprint, **info):
        """Get us a RSA object from our private key on disk"""
        if fingerprint in self.rsa_objs:
            return self.rsa_objs[fingerprint]

        if fingerprint not in self.private_keys:
            raise BadPrivateKey("Don't have a private key for specified fingerprint", fingerprint=fingerprint)

        location = self.private_keys[fingerprint]
        log.debug("Using private key at %s (%s) to decrypt (%s)", location, fingerprint, " || ".join("{0}={1}".format(key, val) for key, val in info.items()))

        key = self.rsaobj_from_location(location)
        if not key:
            raise BadPrivateKey("Couldn't decode the key", location=location)

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

