from credo.asker import ask_for_choice_or_new
from credo.errors import NoAccountIdEntered
from credo.amazon import IamPair

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
        """Return the account id for this account"""
        if not getattr(self, "_account_id", None):
            self._account_id = self.recorded_account_id()
            if not self._account_id:
                account_id = self.ask_for_account_id(suggestion, iam_pair)
                fingerprint, signature = self.crypto.create_signature(self.signature_value(self.repo_name, self.name, account_id))

                info_location = self.account_info_location
                dirname = os.path.dirname(info_location)
                if not os.path.exists(dirname):
                    os.makedirs(dirname)

                with open(info_location, "w") as fle:
                    fle.write("{0},{1},{2}".format(account_id, fingerprint, signature))

                commit_message = "Writing account id {0} for repo {1}, account {2}".format(account_id, self.repo_name, self.name)
                self.credential_path.add_change(commit_message, [info_location])

                self._account_id = account_id
        return self._account_id

    def recorded_account_id(self):
        """Read our current account id"""
        incorrect = False
        account_id = None
        id_location = self.account_info_location

        if os.path.exists(id_location) and os.access(id_location, os.R_OK):
            with open(id_location) as fle:
                contents = fle.read().strip().split("\n")[0]

            if contents.count(',') != 2:
                incorrect = True
            else:
                account_id, fingerprint, signature = contents.split(',')
                if not self.crypto.is_signature_valid(self.signature_value(self.repo_name, self.name, account_id), fingerprint, signature):
                    incorrect = True

        if incorrect:
            log.error("Was something corrupt about the account_id file\tlocation=%s", id_location)
            return

        return account_id

    def signature_value(self, repo, account, account_id):
        """Return string for signing in the account_id file"""
        return "{0}|{1}|{2}".format(repo, account, account_id)

    def ask_for_account_id(self, suggestion, iam_pair):
        """Get an account id from the user"""
        choices = ["Quit"]

        if suggestion:
            suggestion = str(suggestion)
            choices.insert(0, suggestion)

        found = None
        if iam_pair:
            try:
                log.info("Asking amazon for account id of current credentials")
                found = iam_pair.ask_amazon_for_account()
            except:
                pass

        if found:
            found = str(found)
            if found != suggestion:
                choices.insert(0, found)

        choice = ask_for_choice_or_new(
              "How do you want to enter the account id?\trepo={0}\taccount={1}".format(self.repo_name, self.name)
            , choices
            )

        if choice == "Quit":
            raise NoAccountIdEntered()
        elif choice == suggestion:
            account_id = suggestion
        elif choice == found:
            account_id = found
        else:
            account_id = choice

        return account_id

