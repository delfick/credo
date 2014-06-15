from credo.errors import (
      BadSSHKey, BadCypherText, BadFolder, CredoError
    , BadPlainText, PasswordRequired, BadPrivateKey, BadPublicKey
    , NoSuchFingerPrint, CantFindPrivateKey, InvalidData
    )
from credo.asker import ask_for_choice, get_response, ask_for_ssh_key_folders

from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto import Random

from binascii import hexlify, unhexlify
from base64 import b64decode, b64encode
from paramiko import Message
import tempfile
import paramiko
import logging
import random
import string
import json
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

    def add_public_key(self, pem_data, location=None):
        """Record this public key"""
        rsaobj = self.rsaobj_from_pem(pem_data)
        fingerprint = self.make_fingerprint(rsaobj)
        self.public_fingerprints[fingerprint] = rsaobj
        if location:
            self.fingerprint_to_location[fingerprint] = location
        return fingerprint

    def remove_public_key(self, fingerprint):
        """Remove this public key"""
        if fingerprint in self.public_fingerprints:
            del self.public_fingerprints[fingerprint]

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
        st = hexlify(rsa_obj.get_fingerprint())
        return ":".join(re.findall("..", st))

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

    def find_keys(self, folder):
        """Find more private and public keys in specified folder"""
        if not os.path.exists(folder):
            raise BadFolder("Doesn't exist", folder=folder)
        if not os.access(folder, os.R_OK):
            raise BadFolder("Not readable", folder=folder)

        for filename in os.listdir(folder):
            location = os.path.join(folder, filename)
            if not filename.endswith(".pub") and filename not in ("known_hosts", "authorized_keys", "config"):
                if os.access(location, os.R_OK):
                    is_private = False
                    try:
                        self.collection.add_private_key(location)
                        is_private = True
                    except BadSSHKey:
                        pass

                    if not is_private:
                        try:
                            with open(location) as fle:
                                self.collection.add_public_key(fle.read(), location)
                        except BadSSHKey:
                            pass

            elif filename.endswith(".pub"):
                try:
                    with open(location) as fle:
                        self.collection.add_public_key(fle.read(), location)
                except BadSSHKey:
                    pass

    def add_public_keys(self, public_keys):
        """Add the specified public keys"""
        fingerprints = {}
        for pem_data in public_keys:
            try:
                location = None
                if (isinstance(pem_data, tuple) or isinstance(pem_data, list)) and len(pem_data) == 2:
                    pem_data, location = pem_data
                fingerprints[pem_data] = self.collection.add_public_key(pem_data, location=location)
            except BadSSHKey as err:
                log.error("Found a bad public key\terr=%s", err)
        return fingerprints

    def remove_public_key(self, fingerprint):
        """Remove a public key from our collection"""
        self.collection.remove_public_key(fingerprint)

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
        self.ssh_key_folders = []

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

    def has_private_keys(self):
        """Return whether we have any private keys"""
        return len(self.private_key_fingerprints) > 0

    def find_keys(self, folder):
        """Find keys to add"""
        if folder not in self.ssh_key_folders:
            self.ssh_key_folders.append(folder)
        return self.keys.find_keys(folder)

    def add_public_keys(self, public_keys):
        """Add public keys"""
        return self.keys.add_public_keys(public_keys)

    def remove_public_key(self, fingerprint):
        """Remove a public key"""
        self.keys.remove_public_key(fingerprint)

    def decryptable(self, fingerprints):
        """Say whether we have a private key for any of these fingerprints"""
        return any(fingerprint in self.keys.collection.private_fingerprints for fingerprint in fingerprints)

    def is_signature_valid(self, signed, fingerprint, signature):
        """Return whether this signature is valid for the signed data"""
        try:
            return self.keys.collection.public_rsaobj_for(fingerprint).verify_ssh_sig(signed, paramiko.Message(unhexlify(signature)))
        except TypeError:
            return False

    def create_signature(self, for_signing):
        """Return a signature given this data"""
        fingerprint = self.keys.collection.get_any_private_fingerprint(need_private_key_for="signing")
        message = self.keys.collection.private_rsaobj_for(fingerprint).sign_ssh_data(for_signing)
        return fingerprint, hexlify(str(message))

    def zip_with_fingerprints(self, pems):
        """Return (fingerprint, pem) for each pem in pems"""
        result = []
        for pem in pems:
            try:
                rsaobj = self.keys.collection.rsaobj_from_pem(pem)
                fingerprint = self.keys.collection.make_fingerprint(rsaobj)
            except BadSSHKey as error:
                log.warning("Found a pem key that was invalid\terror=%s", error)

            result.append((fingerprint, pem))
        return result

    def retrieve_public_key_from_disk(self, fingerprint, reason=None):
        """Get this fingerprint and return whether we successfully did so"""
        if self.keys.collection.location_for_fingerprint(fingerprint):
            return True

        def make_ssh_key_location(folders):
            """Get a string to say where we have ssh key folders"""
            if len(self.ssh_key_folders) == 1:
                return self.ssh_key_folders[0]
            else:
                return "one of {0}".format(", ".join(self.ssh_key_folders))

        def add_more_ssh_key_folders():
            """Add more ssh key folders"""
            more_ssh_key_folders = ask_for_ssh_key_folders(already_have=self.ssh_key_folders)
            self.ssh_key_folders.extend(more_ssh_key_folders)

        while not self.ssh_key_folders:
            add_more_ssh_key_folders()
        ssh_key_locations = make_ssh_key_location(self.ssh_key_folders)

        while True:
            if self.keys.collection.location_for_fingerprint(fingerprint):
                return True

            ignore_choice = "I don't have this key"
            try_again_choice = "I've added the key to {0}".format(ssh_key_locations)
            have_another_ssh_key_folder = "I have another folder with ssh keys in it"
            choice = ask_for_choice("Looking for a public key with fingerprint {0}".format(fingerprint), choices=[ignore_choice, try_again_choice, have_another_ssh_key_folder])
            if choice == ignore_choice:
                return False
            elif choice == try_again_choice:
                continue
            elif choice == have_another_ssh_key_folder:
                add_more_ssh_key_folders()
                ssh_key_locations = make_ssh_key_location(self.ssh_key_folders)

            self.keys.find_public_keys()

    def decrypt_by_fingerprint(self, fingerprints, verifier, **info):
        """Return the first valid decrypted value"""
        for fingerprint, values in fingerprints.items():
            if self.keys.have_private(fingerprint) and set(["secret", "data", "verifier"]) - set(values.keys()) == set():
                verifier_val = values['verifier']
                if not isinstance(verifier_val, list) or len(verifier_val) != 2:
                    log.error("Ignoring value with invalid verifier (Verifier is not a list of [fingerprint, signature])")
                    continue

                fingerprint, signature = verifier_val
                encrypted_data = values['data']
                encrypted_secret = values['secret']

                secret = self.keys.decrypt(encrypted_secret, fingerprint, key_fingerprint=fingerprint, action="decrypting", value="Secret for decrypting with")
                decrypted_data = self.decrypt_with_secret(encrypted_data, secret)

                decrypted = None
                try:
                    decrypted = json.loads(decrypted_data)
                except (ValueError, TypeError) as error:
                    log.error("Couldn't load decrypted data as a json dictionary\terror_type=%s\terror=%s\tfingerprint=%s", error.__class__.__name__, error, fingerprint)

                if decrypted:
                    if not self.is_signature_valid(secret, fingerprint, signature):
                        log.error("Ignoring decrypted secrets, because can't verify signature\tfingerprint=%s", fingerprint)
                    else:
                        if not verifier(decrypted):
                            log.error("Ignoring invalid data")
                        else:
                            return decrypted

    def fingerprinted(self, decrypted_vals, **info):
        """
        Return dictionary of {<fingerprint>: {secret: <secret>, data:<data>, verifier:<verifier>}

        Where <secret> is a randomly generated secret
        <data> is the original data encrypted with AES using that secret
        and <verifier> is a signature that says the secret was created using this private key

        Decrypted_vals is assumed to be a json dictionary
        """
        if not isinstance(decrypted_vals, dict):
            raise CredoError("Fingerprinted should only be called with dictionaries", got_type=type(decrypted_vals))

        try:
            data_str = json.dumps(decrypted_vals, sort_keys=True)
        except (ValueError, TypeError) as error:
            raise InvalidData("Couldn't dump values for encryption", error_type=error.__class__.__name__, error=error, **info)

        result = {}
        for fingerprint in self.public_key_fingerprints:
            secret = self.generate_secret()
            verifier = self.create_signature(secret)
            encrypted_data = self.encrypt_with_secret(data_str, secret)
            log.info("Encrypting credentials using AES\tfingerprint=%s", fingerprint)
            encrypted_secret = self.keys.encrypt(secret, fingerprint, key_fingerprint=fingerprint, action="encrypting", value="Secret for encrypting with")
            result[fingerprint] = dict(secret=encrypted_secret, verifier=verifier, data=encrypted_data)

        return result

    def generate_secret(self, key_size=256):
        """Generate a secret that may be used for encrypting values"""
        return Random.OSRNG.posix.new().read(key_size // 8)

    def encrypt_with_secret(self, data, secret):
        """Return the data as an encrypted value, using AES with the provided secret"""
        def pad(s):
            x = AES.block_size - len(s) % AES.block_size
            return s + ''.join([random.choice(string.ascii_letters + string.digits) for n in range(x)])

        padded_message = pad(data)
        iv = Random.OSRNG.posix.new().read(AES.block_size)
        cipher = AES.new(secret, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(padded_message))

    def decrypt_with_secret(self, ciphertext, secret):
        """Return the decrypted value of the ciphtertext using AES with the provided secret"""
        unpad = lambda s: s[:s.rfind("}")+1]
        decoded = b64decode(ciphertext)
        iv = decoded[:AES.block_size]
        cipher = AES.new(secret, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(decoded)[AES.block_size:])

