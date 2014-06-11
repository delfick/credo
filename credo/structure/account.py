from credo.helper import SignedValueFile

import logging
import os

log = logging.getLogger("credo.account")

class Account(object):
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
    def account_info_location(self):
        """Location of where our account id is"""
        return os.path.join(self.location, "account_id")

    def account_id(self, suggestion=None, iam_pair=None):
        """
        Get us the account id for this account
        use suggestion and iam_pair to assist the user in choosing a value if there is none
        """
        if hasattr(self, "_account_id"):
            return self._account_id
        else:
            def suggestions():
                """Get us suggestions from suggestion and iam_pair"""
                result = []
                if suggestion:
                    result.append(suggestion)
                if iam_pair:
                    try:
                        log.info("Asking amazon for account id of current credentials")
                        result.append(iam_pair.ask_amazon_for_account())
                    except:
                        pass
                return result

            info_location = self.account_info_location
            signed_value_file = SignedValueFile(info_location, self.crypto, dict(repo=self.repo_name, account=self.name))
            question = "How do you want to enter the account id?\trepo={0}\taccount={1}".format(self.repo_name, self.name)
            account_id, created = signed_value_file.retrieve("Account ID", question, suggestions)

            if created:
                self.credential_path.add_change("Writing account id {0}".format(account_id), [info_location], repo=self.repo_name, account=self.name)

            self._account_id = account_id

        return self._account_id

