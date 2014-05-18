from credo.credentials import AmazonCredentials
from credo.errors import BadCredentialFile

from collections import namedtuple
import json
import os

CredentialInfo = namedtuple("CredentialInfo", ("location", "repo", "account", "user"))

class Loader(object):
    """Knows how to load credentials from a file"""

    @classmethod
    def from_file(kls, credential_info, crypto, default_type=None):
        """Return Credentials object representing this location"""
        loader = kls()
        contents = {"keys": [], "type": default_type or "amazon"}
        if os.path.exists(credential_info.location):
            contents = loader.read(credential_info.location)

        if "keys" in contents:
            if not isinstance(contents["keys"], list):
                raise BadCredentialFile("Credentials file keys are not a list", keys=type(contents["keys"]))

        typ = contents.get("type", "amazon")
        if typ != "amazon":
            raise BadCredentialFile("Unknown credentials type", found=typ)

        return AmazonCredentials(typ, credential_info, contents, crypto)

    def read(self, location):
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
            raise BadCredentialFile("Credentials file not valid json", location=location, error=err)

