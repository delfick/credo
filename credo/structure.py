from credo.errors import BadCredentialFile, BadCredential
from credo.asker import ask_for_choice_or_new
from credo.amazon import AmazonKeys, IamPair
from credo.errors import NoAccountIdEntered
from credo.versioning import Repository

from collections import namedtuple
import logging
import copy
import json
import os

log = logging.getLogger("credo.structure")

class Credentials(object):
    """Knows about credential files"""

    def __init__(self, credential_info, crypto):
        self.crypto = crypto
        self.credential_info = credential_info
        self._changed = False

    def load(self):
        """Load the keys from our credentials file"""
        self.contents = self.credential_info.contents
        self.typ = self.contents.get("type", "amazon")
        if self.typ != "amazon":
            raise BadCredential("Unknown credential type", found=self.typ, location=self.credential_info.location)

        if hasattr(self, "keys"):
            self._changed = True
        self.keys = AmazonKeys(self.contents.get("keys"), self.credential_info, self.crypto)

    @property
    def working_keys(self):
        """Return the keys that are working"""
        return [key for key in self.keys if key.iam_pair and key.iam_pair.works]

    @property
    def changed(self):
        return self._changed or (hasattr(self, "keys") and self.keys.changed)

    @property
    def location(self):
        return self.credential_info.location

    def add_key(self, aws_access_key_id, aws_secret_access_key, create_epoch=None, half_life=None):
        """Add a key"""
        iam_pair = IamPair(aws_access_key_id, aws_secret_access_key, create_epoch, half_life)
        self._changed = True
        return self.keys.add_key(iam_pair)

    @property
    def encrypted_values(self):
        """Return _values as a dictionary with some encrypted values"""
        contents = copy.deepcopy(self.contents)
        contents["keys"] = self.keys.encrypted_values
        return contents

    def save(self, force=False):
        """Write our values to our json file"""
        if not self.changed and not force and all(key.iam_pair and key.iam_pair.works for key in self.keys):
            # Nothing new to save
            return

        dirname = os.path.dirname(self.location)
        if not os.path.exists(dirname):
            try:
                os.makedirs(dirname)
            except OSError as err:
                raise BadCredentialFile("Can't create parent directory", err=err)

        if not os.access(dirname, os.W_OK):
            raise BadCredentialFile("Don't have write permissions to parent directory", location=self.location)

        try:
            log.info("Making encrypted values for %s keys using %s public keys", len(self.working_keys), len(self.crypto.public_key_fingerprints))
            vals = self.encrypted_values
        except UnicodeDecodeError as err:
            raise BadCredentialFile("Can't get encrypted values for the credentials file!", err=err, location=self.location)

        try:
            contents = json.dumps(vals, indent=4)
        except ValueError as err:
            raise BadCredentialFile("Can't create credentials as json", err=err, location=self.location)

        try:
            info = self.credential_info
            log.info("Saving credentials for %s|%s|%s to %s with access_keys %s", info.repo, info.account, info.user, info.location, list(self.keys.access_keys))
            with open(self.location, "w") as fle:
                fle.write(contents)
            self.unchanged()
        except OSError as err:
            raise BadCredentialFile("Can't write to the credentials file", err=err, location=self.location)

    def needs_rotation(self):
        """Works out if our current keys need rotation"""
        return self.keys.needs_rotation()

    def rotate(self):
        """Rotate the credentials and return whether anything changed"""
        change = self.keys.rotate()
        if change:
            self._changed = True
        return change

    def shell_exports(self):
        """Return list of (key, val) exports we want to have in the shell"""
        return self.keys.exports() + [
              ("CREDULOUS_CURRENT_REPO", self.credential_info.repo)
            , ("CREDULOUS_CURRENT_ACCOUNT", self.credential_info.account)
            , ("CREDULOUS_CURRENT_USER", self.credential_info.user)
            ]

    def unchanged(self):
        """Reset changed on everything"""
        self._changed = False
        self.keys.unchanged()

    def as_string(self):
        """Return information about credentials as a string"""
        return "Credentials!"

def read_credentials(location):
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

class CredentialInfo(namedtuple("CredentialInfo", ("location", "repo", "account", "user"))):
    @property
    def repository(self):
        """Return an object representing the repository"""
        if not getattr(self, "_repository", None):
            repo_location = os.path.abspath(os.path.join(os.path.dirname(self.location), "..", ".."))
            self._repository = Repository(repo_location)

        return self._repository

    @property
    def contents(self):
        """Return the contents from the credentials file as a dictionary"""
        contents = {"keys": [], "type": "amazon"}
        if os.path.exists(self.location):
            contents = read_credentials(self.location)

        if "keys" in contents:
            if not isinstance(contents["keys"], list):
                raise BadCredentialFile("Credentials file keys are not a list", keys=type(contents["keys"]))

        return contents

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

