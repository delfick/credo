from credulous.asker import ask_user_for_secrets
from credulous.errors import BadCredentialFile

from crypto import Crypto
import copy
import json
import os

class Credentials(object):
    """Knows about credential files"""
    needs_encryption = ["access_key", "secret_key"]

    def __init__(self, location, repo, account, user):
        self.crypto = Crypto()

        self.user = user
        self.repo = repo
        self.account = account
        self.location = location

    @classmethod
    def make(kls, location, repo, account, user):
        credentials = kls(location, repo, account, user)
        access_key, secret_key = ask_user_for_secrets()
        credentials.override_file(access_key=access_key, secret_key=secret_key)
        return credentials

    def override_file(self, **overrides):
        """Override values in our file"""
        values = {}
        try:
            values = self.read()
        except:
            pass

        values.update(overrides)
        self._values = values

    @property
    def access_key(self):
        return self.values["access_key"]

    @property
    def secret_key(self):
        return self.values["secret_key"]

    @property
    def values(self):
        """Read in and decrypt our values and memoize the result"""
        if not hasattr(self, "_values"):
            self._values = self.read()
            for key in self.needs_encryption:
                if key in self._values:
                    self._values[key] = self.decrypt(self._values[key], decrypting=key, location=self.location)
        return self._values

    @property
    def encrypted_values(self):
        """Return _values as a dictionary with some encrypted values"""
        values = copy.deepcopy(self.values)
        for key in self.needs_encryption:
            if key in values:
                values[key] = self.encrypt(values[key], encrypting=key)
        return values

    def read(self):
        """Read in our location as a json file"""
        if not os.path.exists(self.location):
            raise BadCredentialFile("Doesn't exist", location=self.location)
        if not os.access(self.location, os.R_OK):
            raise BadCredentialFile("Don't have read permissions", location=self.location)

        if os.stat(self.location).st_size == 0:
            raise BadCredentialFile("Credentials file is empty!", location=self.location)

        try:
            return json.load(open(self.location))
        except ValueError as err:
            raise BadCredentialFile("Credentials file not valid json", location=self.location, error=err)

    def save(self):
        """Write our values to our json file"""
        dirname = os.path.dirname(self.location)
        if not os.path.exists(dirname):
            try:
                os.makedirs(dirname)
            except OSError as err:
                raise BadCredentialFile("Can't create parent directory", err=err)

        if not os.access(dirname, os.W_OK):
            raise BadCredentialFile("Don't have write permissions to parent directory", location=self.location)

        try:
            json.dump(self.encrypted_values, open(self.location, 'w'))
        except ValueError as err:
            raise BadCredentialFile("Can't write credentials as json", err=err, location=self.location)

    def shell_exports(self):
        """Return list of (key, val) exports we want to have in the shell"""
        return [
              ("AWS_ACCESS_KEY_ID", self.access_key)
            , ("AWS_SECRET_ACCESS_KEY", self.secret_key)
            , ("CREDULOUS_CURRENT_REPO", self.repo)
            , ("CREDULOUS_CURRENT_ACCOUNT", self.account)
            , ("CREDULOUS_CURRENT_USER", self.user)
            ]

    def decrypt(self, value, **info):
        """
        Decrypt the specified value
        Also figure out what private key to use
        """
        fingerprint = self.values.get("fingerprint", None)
        private_key_loc = self.crypto.find_key_for_fingerprint(fingerprint, default="id_rsa")
        return self.crypto.decrypt(value, private_key_loc, **info)

    def encrypt(self, value, **info):
        """
        Encrypt the specified value
        And figure out what public keys to encrypt with
        """
        public_key_loc = os.path.expanduser("~/.ssh/id_rsa.pub")
        return self.crypto.encrypt(value, public_key_loc, **info)

    def as_string(self):
        """Return information about credentials as a string"""
        return "Credentials!"

