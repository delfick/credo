from credo.cred_types.environment import EnvironmentMixin
from credo.helper import SignedValueFile

import logging
import os

log = logging.getLogger("credo.structure.user")

class User(object, EnvironmentMixin):
    def __init__(self, name, location, credential_path):
        self.name = name
        self.location = location
        self.credential_path = credential_path

    @property
    def crypto(self):
        """Proxy credential_path"""
        return self.credential_path.crypto

    @property
    def repo_name(self):
        """Proxy credential_path"""
        return self.credential_path.repository.name

    @property
    def account_name(self):
        """Proxy credential_path"""
        return self.credential_path.account.name

    @property
    def username_location(self):
        """Location of where our username is"""
        return os.path.join(self.location, "username")

    @property
    def path(self):
        """Return the repo, account and user this represents"""
        return "repo={0}|account={1}|user={2}".format(self.repo_name, self.account_name, self.name)

    @property
    def parent_path_part(self):
        """Return our account"""
        return self.credential_path.account

    def extra_env(self):
        """Define default env stuff"""
        return [("CREDO_CURRENT_USER", self.name)]

    def username(self, suggestion=None, iam_pair=None):
        """
        Get us the amazon username for this user
        use suggestion and iam_pair to assist the user in choosing a value if there is none
        """
        if hasattr(self, "_username"):
            return self._username
        else:
            def suggestions():
                """Get us suggestions from suggestion and iam_pair"""
                result = []
                if suggestion:
                    result.append(suggestion)
                if iam_pair:
                    try:
                        result.append(iam_pair.ask_amazon_for_username())
                    except:
                        pass
                return result

            info_location = self.username_location
            signed_value_file = SignedValueFile(info_location, self.crypto, dict(repo=self.repo_name, account=self.account_name, username=self.name))
            question = "How do you want to enter the username?\trepo={0}\taccount={1}\tusername={2}".format(self.repo_name, self.account_name, self.name)
            username, created = signed_value_file.retrieve("Username", question, suggestions)

            if created:
                self.credential_path.add_change("Writing username {0}".format(username), [info_location], repo=self.repo_name, account=self.account_name, username=self.name)

            self._username = username

        return self._username

