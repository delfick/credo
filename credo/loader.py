from credo.errors import BadCredentialFile, NoAccountIdEntered
from credo.credentials import AmazonCredentials
from credo.asker import ask_for_choice_or_new

from collections import namedtuple
import logging
import json
import os

log = logging.getLogger("credo.loader")

class CredentialInfo(namedtuple("CredentialInfo", ("location", "repo", "account", "user"))):
    def get_account_id(self, crypto):
        """Return the account id for this account"""
        if not getattr(self, "_account_id", None):
            found = False
            incorrect = False
            account_id = None
            account_location = os.path.abspath(os.path.join(os.path.dirname(self.location), ".."))
            id_location = os.path.join(account_location, "account_id")

            if os.path.exists(id_location) and os.access(id_location, os.R_OK):
                found = True
                with open(id_location) as fle:
                    contents = fle.read().strip().split("\n")[0]

                if contents.count(',') != 2:
                    incorrect = True
                else:
                    account_id, fingerprint, signature = contents.split(',')
                    if not crypto.is_signature_valid(account_id, fingerprint, signature):
                        incorrect = True

            if incorrect:
                log.error("Was something corrupt about the account_id file under %s", account_location)

            if incorrect or not found:
                choices = ["Quit"]
                choose_choice = "Choose {0}".format(account_id)
                if account_id:
                    choices.insert(0, choose_choice)

                choice = ask_for_choice_or_new("How do you want to enter the account id for {0}?".format(os.path.basename(account_location)), choices)
                if choice == "Quit":
                    raise NoAccountIdEntered()
                elif choice != choose_choice:
                    account_id = choice

            fingerprint, signature = crypto.create_signature(account_id)
            with open(id_location, "w") as fle:
                fle.write("{0},{1},{2}".format(account_id, fingerprint, signature))

            self._account_id = account_id
        return self._account_id

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

