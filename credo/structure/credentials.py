from credo.errors import BadCredentialFile
from credo.amazon import AmazonKeys

import logging
import json
import os

log = logging.getLogger("credo.structure")

class KeysFile(object):
    """Understands how to load and save to a keys file"""
    def read_file(self, location):
        """Read in our location as a json file"""
        if not os.path.exists(location):
            raise BadCredentialFile("Doesn't exist", location=location)
        if not os.access(location, os.R_OK):
            raise BadCredentialFile("Don't have read permissions", location=location)

        if os.stat(location).st_size == 0:
            return {}

        try:
            return json.load(open(location))
        except ValueError as err:
            raise BadCredentialFile("Keys file not valid json", location=location, error=err)

    def load(self, location):
        """Load the keys from our keys file"""
        contents = {"keys": [], "type": "amazon"}
        if os.path.exists(location):
            contents = self.read_file(location)

        if not isinstance(contents.get("keys", []), list):
            raise BadCredentialFile("Keys file keys are not a list", keys=type(contents["keys"]))

        self.contents = contents
        self.typ = self.contents.get("type", "amazon")
        self.keys = self.contents.get("keys", [])

    def save(self, location, keys):
        """Save the provided keys to this location"""
        dirname = os.path.dirname(location)
        if not os.path.exists(dirname):
            try:
                os.makedirs(dirname)
            except OSError as err:
                raise BadCredentialFile("Can't create parent directory", err=err)

        if not os.access(dirname, os.W_OK):
            raise BadCredentialFile("Don't have write permissions to parent directory", location=self.location)

        try:
            key_vals = keys.encrypted_values
        except UnicodeDecodeError as err:
            raise BadCredentialFile("Can't get encrypted values for the keys file!", err=err, location=self.location)

        try:
            vals = {"type": keys.type, "keys": key_vals}
            contents = json.dumps(vals, indent=4)
        except ValueError as err:
            raise BadCredentialFile("Can't create keys as json", err=err, location=self.location)

        try:
            with open(location, "w") as fle:
                log.info("Saving keys to %s with access_keys %s", location, list(keys.access_keys))
                fle.write(contents)
        except OSError as err:
            raise BadCredentialFile("Can't write to the credentials file", err=err, location=self.location)

class Credentials(object):
    """Knows about credential files"""
    def __init__(self, location, credential_path):
        self.location = location
        self.credential_path = credential_path

    def load(self):
        """Just return the contents"""
        return self.contents

    def save(self, force=False):
        """Save our credentials to file"""
        if self.keys.needs_rotation():
            self.keys.rotate()

        if force or self.keys.changed:
            self.contents.save(self.location, self.keys)
            self.keys.unchanged()

    @property
    def contents(self):
        """Get us the contents"""
        if not hasattr(self, "_contents"):
            self._contents = KeysFile()
            self._contents.load(self.location)
        return self._contents

    @property
    def keys(self):
        """Get us some keys"""
        if not hasattr(self, "_keys"):
            if self.contents.typ != "amazon":
                raise BadCredentialFile("Unknown credentials type", found=self.contents.typ, location=self.contents.location)
            self._keys = AmazonKeys(self.contents.keys, self.credential_path)
        return self._keys

    def shell_exports(self):
        """Return list of (key, val) exports we want to have in the shell"""
        cred_path = self.credential_path
        return self.keys.exports() + [
              ("CREDO_CURRENT_REPO", cred_path.repository.name)
            , ("CREDO_CURRENT_USER", cred_path.user.name)
            , ("CREDO_CURRENT_ACCOUNT", cred_path.account.name)
            ]

    def as_string(self):
        """Return information about keys as a string"""
        return "keys!"

