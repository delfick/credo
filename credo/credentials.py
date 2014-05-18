from credo.asker import ask_user_for_secrets
from credo.errors import BadCredentialFile
from credo.rotator import Rotator

from crypto import Crypto
import logging
import copy
import json
import os

log = logging.getLogger("credo.credentials")

class Credentials(object):
    """Knows about credential files"""
    needs_encryption = ["aws_access_key_id", "aws_secret_access_key"]

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
        if not os.path.exists(location):
            credentials._values = {}

        already_have = False
        for values in credentials.values.values():
            if values.get("aws_access_key_id") == access_key and values.get("aws_secret_access_key") == secret_key:
                already_have = True

        if not already_have:
            credentials._values, _, _ = credentials.rotate(access_key, secret_key)
        else:
            log.info("Already have those credentials!")

        return credentials

    @property
    def aws_access_key_id(self):
        return self.current_key["aws_access_key_id"]

    @property
    def aws_secret_access_key(self):
        return self.current_key["aws_secret_access_key"]

    @property
    def current_key(self):
        """Get the current key to use and rotate if we need to"""
        self._values, current, _ = self.rotate()
        return current

    @property
    def access_keys(self):
        """Get all the known access keys"""
        result = []
        for value in self.values.values():
            if "aws_access_key_id" in value:
                result.append(value["aws_access_key_id"])
        return result

    @property
    def values(self):
        """Read in and decrypt our values and memoize the result"""
        if not hasattr(self, "_values"):
            self._values = self.read()
            for key_values in self._values.values():
                for key in self.needs_encryption:
                    if key in key_values:
                        key_values[key] = self.decrypt(key_values[key], decrypting=key, location=self.location)
        return self._values

    @property
    def encrypted_values(self):
        """Return _values as a dictionary with some encrypted values"""
        values = copy.deepcopy(self.values)
        for key_values in values.values():
            for key in self.needs_encryption:
                if key in key_values:
                    key_values[key] = self.encrypt(key_values[key], encrypting=key)
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
            vals = self.encrypted_values
        except UnicodeDecodeError as err:
            raise BadCredentialFile("Can't get encrypted values for the credentials file!", err=err, location=self.location)

        try:
            contents = json.dumps(vals)
        except ValueError as err:
            raise BadCredentialFile("Can't create credentials as json", err=err, location=self.location)

        try:
            with open(self.location, "w") as fle:
                log.info("Saving credentials for %s|%s|%s with access_keys %s", self.repo, self.account, self.user, self.access_keys)
                fle.write(contents)
        except OSError as err:
            raise BadCredentialFile("Can't write to the credentials file", err=err, location=self.location)

    def shell_exports(self):
        """Return list of (key, val) exports we want to have in the shell"""
        return [
              ("AWS_ACCESS_KEY_ID", self.aws_access_key_id)
            , ("AWS_SECRET_ACCESS_KEY", self.aws_secret_access_key)
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
        return self.crypto.encrypt(str(value), public_key_loc, **info)

    def as_string(self):
        """Return information about credentials as a string"""
        return "Credentials!"

    def rotate(self, access_key=None, secret_key=None):
        """Rotate our keys and return what the new values should be"""
        return Rotator().rotate(self.values, self.user, access_key=access_key, secret_key=secret_key)

