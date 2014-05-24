from credo.errors import (
      BadSSHKey, BadCypherText, BadFolder, CredoError
    , BadPlainText, PasswordRequired, BadPrivateKey, BadPublicKey
    , NoSuchFingerPrint, CantFindPrivateKey
    )
from credo.asker import ask_for_choice, get_response

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from binascii import hexlify, unhexlify
from base64 import b64decode
from paramiko import Message
import tempfile
import paramiko
import logging
import os
import re

log = logging.getLogger("credo.crypto")

class KeyCollection(object):
    """Keeps private and public keys"""
    def __init__(self):
        self.public_fingerprints = {}
        self.private_fingerprints = {}

        self.private_key_locations = {}
        self.fingerprint_to_location = {}

        self._location_to_public_rsaobj = {}
        self._location_to_private_rsaobj = {}

        self._location_to_fingerprint = {}

    def get_any_private_fingerprint(self, **info):
        """Get any of the private fingerprints"""
        fullfilled = [fingerprint for fingerprint, rsaobj in self.private_fingerprints.items() if rsaobj and fingerprint in self.public_fingerprints]
        if fullfilled:
            return fullfilled[0]

        # None already, let's get one that we have a public key for
        unfullfilled = [fingerprint for fingerprint, rsaobj in self.private_fingerprints.items() if fingerprint in self.public_fingerprints]
        if unfullfilled:
            return self.make_fingerprint(self.private_rsaobj_for(unfullfilled[0]))

        raise CantFindPrivateKey(**info)

    def add_public_key(self, pem_data):
        """Record this public key"""
        rsaobj = self.rsaobj_from_pem(pem_data)
        fingerprint = self.make_fingerprint(rsaobj)
        self.public_fingerprints[fingerprint] = rsaobj
        return fingerprint

    def add_private_key(self, location):
        """
        Record this private key

        Only get the fingerprint from the public key for now if it needs a password
        So we can delay getting the password till it's absolutely necessary
        """
        rsaobj = self.rsaobj_from_location(location, only_need_public=True)
        fingerprint = self.make_fingerprint(rsaobj)
        self.private_fingerprints[fingerprint] = None
        self.private_key_locations[fingerprint] = location
        self.fingerprint_to_location[fingerprint] = location
        return fingerprint

    def location_for_fingerprint(self, fingerprint):
        """Return the location of the fingerprint if we have one"""
        return self.fingerprint_to_location.get(fingerprint)

    def public_pem_for(self, fingerprint):
        """Get the public pem data for this fingerprint"""
        return "ssh-rsa {0}".format(self.public_rsaobj_for(fingerprint).get_base64())

    def public_rsaobj_for(self, fingerprint):
        """Get the rsaobj for this public fingerprint"""
        if fingerprint in self.public_fingerprints:
            return self.public_fingerprints[fingerprint]

        if fingerprint in self.private_fingerprints:
            return self.private_fingerprints[fingerprint]

        raise NoSuchFingerPrint(fingerprint=fingerprint, looking_for="public")

    def private_rsaobj_for(self, fingerprint):
        """
        Get the rsaobj for this private fingerprint

        If we don't have the rsaobj but we do have the location,
        then we get the rsaobj for the private part as well first
        """
        if not self.private_fingerprints.get(fingerprint):
            if fingerprint not in self.private_key_locations:
                raise NoSuchFingerPrint(fingerprint=fingerprint, looking_for="private")

            rsaobj = self.rsaobj_from_location(self.private_key_locations[fingerprint])
            self.private_fingerprints[fingerprint] = rsaobj

        return self.private_fingerprints[fingerprint]

    def make_fingerprint(self, rsa_obj):
        """Get us a fingerprint from this rsa_obj"""
        string = hexlify(rsa_obj.get_fingerprint())
        return ":".join(re.findall("..", string))

    def rsaobj_from_pem(self, pem_data):
        """Get us a paramiko.RSAKey from a public key pem_data."""
        tmp = None
        try:
            tmp = tempfile.NamedTemporaryFile(delete=True).name
            with open(tmp, 'w') as fle:
                fle.write(pem_data)
            return self.make_rsakey(tmp)
        finally:
            if tmp and os.path.exists(tmp):
                os.remove(tmp)

    def rsaobj_from_location(self, location, only_need_public=False):
        """
        Get us a paramiko.RSAKey from this location

        If the location is a password protected private key and only_need_public then we look for a public key
        If we can't find a public key, then we ask for the password and get the fingerprint that way

        If it isn't a private key, then we raise a credo.NotSSHKey exception
        """
        if only_need_public:
            if location in self._location_to_public_rsaobj:
                return self._location_to_public_rsaobj[location]
        else:
            if location in self._location_to_private_rsaobj:
                return self._location_to_private_rsaobj[location]

        rsaobj = None
        try:
            rsaobj = self.make_rsakey(location, private=True)
            self._location_to_private_rsaobj[location] = rsaobj
        except PasswordRequired:
            if only_need_public:
                pub_key = "{0}.pub".format(location)
                if os.path.exists(pub_key):
                    try:
                        rsaobj = self.make_rsakey(pub_key)
                        self._location_to_public_rsaobj[location] = rsaobj
                    except BadSSHKey as err:
                        log.info("Something wrong with public key %s: %s", pub_key, err)

        if rsaobj is None:
            while True:
                if only_need_public:
                    log.info("Couldn't find a public key for password protected private key at %s", location)

                password = get_response("Password for your private key ({0})".format(location), password=True)

                try:
                    rsaobj = self.make_rsakey(location, password=password, private=True)
                    self._location_to_private_rsaobj[location] = rsaobj
                    break
                except BadSSHKey:
                    choice = ask_for_choice("Couldn't decode the key ({0})".format(location), ["Try again", "Ignore"])
                    if choice == "Ignore":
                        return

        return rsaobj

    def make_rsakey(self, location, password=None, private=False):
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

class SSHKeys(object):
    """Stores private and public ssh keys by fingerprint"""
    def __init__(self):
        self._RSA = {}
        self.collection = KeyCollection()

    def have_private(self, fingerprint):
        """Says whether we have a private key with this fingerprint"""
        return fingerprint in self.collection.private_fingerprints

    def have_public(self, fingerprint):
        """Says whether we have a public key with this fingerprint"""
        return fingerprint in self.collection.public_fingerprints

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
                        self.collection.add_private_key(location)
                    except BadSSHKey:
                        pass

    def add_public_keys(self, public_keys):
        """Add the specified public keys"""
        fingerprints = {}
        for pem_data in public_keys:
            try:
                fingerprints[pem_data] = self.collection.add_public_key(pem_data)
            except BadSSHKey as err:
                log.error("Found a bad public key\terr=%s", err)
        return fingerprints

    def private_key_to_rsa_object(self, fingerprint, **info):
        """Get us a RSA object from our private key on disk"""
        if fingerprint in self._RSA:
            return self._RSA[fingerprint]

        if not self.have_private(fingerprint):
            raise BadPrivateKey("Don't have a private key for specified fingerprint", fingerprint=fingerprint)

        key = self.collection.private_rsaobj_for(fingerprint)
        location = self.collection.location_for_fingerprint(fingerprint)
        location_str = ""
        if location:
            location_str = "at {0} ".format(location)
        log.debug("Using private key %s(%s) to decrypt (%s)", location_str, fingerprint, " || ".join("{0}={1}".format(key, val) for key, val in info.items()))

        key = RSA.construct((key.n, key.e, key.d, key.p, key.q))
        self._RSA[fingerprint] = key
        return key

    def encrypt(self, message, fingerprint, **info):
        """Encrypt the specified message using specified public key and return as base64 encoded string"""
        log.debug("Using public key with fingerprint %s to encrypt (%s)", fingerprint, " || ".join("{0}={1}".format(key, val) for key, val in info.items()))
        rsakey = RSA.importKey(self.collection.public_pem_for(fingerprint))
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

class Crypto(object):
    """Knows how to do crypto"""
    def __init__(self, keys=None):
        if keys is None:
            keys = SSHKeys()
        self.keys = keys

    @property
    def can_encrypt(self):
        """Say whether we have any public keys"""
        return self.has_public_keys()

    @property
    def can_sign(self):
        """Say whether we have private keys with corresponding public keys"""
        return self.has_public_keys() and any(fingerprint in self.public_key_fingerprints for fingerprint in self.private_key_fingerprints)

    @property
    def private_key_fingerprints(self):
        """Proxy our key collection"""
        return self.keys.collection.private_fingerprints.keys()

    @property
    def public_key_fingerprints(self):
        """Proxy our key collection"""
        return self.keys.collection.public_fingerprints.keys()

    def has_public_keys(self):
        """Return whether we have any public keys"""
        return len(self.public_key_fingerprints) > 0

    def find_private_keys(self, folder):
        """Find keys to add"""
        return self.keys.find_private_keys(folder)

    def add_public_keys(self, public_keys):
        """Add public keys"""
        return self.keys.add_public_keys(public_keys)

    def decryptable(self, fingerprints):
        """Say whether we have a private key for any of these fingerprints"""
        return any(fingerprint in self.keys.collection.private_fingerprints for fingerprint in fingerprints)

    def is_signature_valid(self, signed, fingerprint, signature):
        """Return whether this signature is valid for the signed data"""
        return self.keys.collection.public_rsaobj_for(fingerprint).verify_ssh_sig(signed, paramiko.Message(unhexlify(signature)))

    def create_signature(self, for_signing):
        """Return a signature given this data"""
        fingerprint = self.keys.collection.get_any_private_fingerprint(need_private_key_for="signing")
        message = self.keys.collection.private_rsaobj_for(fingerprint).sign_ssh_data(for_signing)
        return fingerprint, hexlify(str(message))

    def decrypt_by_fingerprint(self, fingerprints, verifier_maker, **info):
        """Yield each different decrypted value if we find any and check against the verifier"""
        found = set()
        for fingerprint, values in fingerprints.items():
            if self.keys.have_private(fingerprint):
                decrypted = {}
                for key, val in values.items():
                    if not key.startswith("_"):
                        info = dict(info)
                        info["key"] = key
                        info["key_fingerprint"] = fingerprint
                        info["action"] = "decrypting"
                        decrypted[key] = self.keys.decrypt(val, fingerprint, **info)

                new_verifier, information = verifier_maker(values, decrypted)
                if not self.is_signature_valid(new_verifier, *values["__account_verifier__"]):
                    log.error("Ignoring decrypted secrets, because can't verify __account_verifier__\t%s", "\t".join("{0}={1}".format(key, val) for key, val in sorted(information.items())))
                else:
                    decrypted["__account_verifier__"] = values["__account_verifier__"]
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
        for fingerprint in self.public_key_fingerprints:
            encrypted = {}
            for key, val in decrypted_vals.items():
                info = dict(info)
                info["key_fingerprint"] = fingerprint
                info["action"] = "encrypting"
                info["key"] = key
                encrypted[key] = self.keys.encrypt(val, fingerprint, **info)

            info["key"] = "__account_verifier__"
            for_signing, information = verifier_maker(encrypted, decrypted_vals)
            encrypted["__account_verifier__"] = self.create_signature(for_signing)
            log.info("Made signature for key\t%s", "\t".join("{0}={1}".format(key, val) for key, val in sorted(information.items())))
            result[fingerprint] = encrypted

        return result

