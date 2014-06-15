from credo.structure.credentials import Credentials
from credo.structure.repository import Repository
from credo.structure.account import Account
from credo.structure.user import User

import os

class CredentialPath(object):
    """Knows about everything leading up to a credentials"""
    user = None
    account = None
    repository = None
    credentials = None

    def __init__(self, crypto):
        self.crypto = crypto

    def fill_out(self, directory_structure, repo, account, user):
        """Make the things leading up to the credentials"""
        self.repository = Repository(repo, directory_structure[repo]['/location/'], self.crypto)
        if account:
            self.account = Account(account, directory_structure[repo][account]['/location/'], self)
            if user:
                self.user = User(user, directory_structure[repo][account][user]['/location/'], self)
                credential_location = os.path.join(self.user.location, "credentials.json")
                self.credentials = Credentials(credential_location, self)

    def add_change(self, location, message, **info):
        """Register a change that was made"""
        self.repository.add_change(location, message, **info)

