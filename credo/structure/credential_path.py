from credo.structure.credentials import Credentials, SamlCredentials
from credo.structure.repository import Repository
from credo.structure.account import Account
from credo.structure.user import User

import logging
import json
import os

log = logging.getLogger("credo.structure.credential_path")

class CredentialPath(object):
    """Knows about everything leading up to a credentials"""
    user = None
    account = None
    repository = None
    credentials = None

    def __init__(self, crypto):
        self.crypto = crypto

    def fill_out(self, directory_structure, repo, account, user, typ="amazon"):
        """Make the things leading up to the credentials"""
        self.repository = Repository(repo, directory_structure[repo]['/location/'], self.crypto)
        if account:
            self.account = Account(account, directory_structure[repo][account]['/location/'], self)
            if user:
                self.user = User(user, directory_structure[repo][account][user]['/location/'], self)
                credential_location = os.path.join(self.user.location, "credentials.json")
                self.credentials = self.make_credentials(credential_location, self, typ)

    def make_credentials(self, location, cred_path, typ="amazon"):
        """Make a credentials object from this location"""
        if os.path.exists(location):
            with open(location) as f:
                contents = None
                try:
                    contents = json.load(f)
                except (ValueError, TypeError) as error:
                    log.warning("Failed to find type of file\terror=%s\tlocation=%s", error, location)

                if contents and isinstance(contents, dict) and 'type' in contents:
                    typ = contents.get("type", typ)

        if typ == "saml":
            return SamlCredentials(location, self)
        else:
            return Credentials(location, self)

    def add_change(self, location, message, **info):
        """Register a change that was made"""
        self.repository.add_change(location, message, **info)

