from credo.errors import BadCredentialFile, NoCredentialsFound, BadCredential, UserQuit
from credo.asker import ask_user_for_half_life, ask_for_choice_or_new

from boto.iam.connection import IAMConnection
import datetime
import hashlib
import logging
import copy
import time
import boto
import json
import sys
import os

log = logging.getLogger("credo.credentials")

class IamPair(object):
    def __init__(self, aws_access_key_id, aws_secret_access_key, create_epoch=None, half_life=None):
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key

        self._half_life = half_life
        self._create_epoch = create_epoch
        self.changed = False
        self.deleted = False

    @property
    def connection(self):
        """Get a connection for these keys"""
        if not getattr(self, "_connection", None):
            self._connection = IAMConnection(self.aws_access_key_id, self.aws_secret_access_key)
        return self._connection

    @property
    def works(self):
        """Says whether this key is valid enough to get iam informations"""
        if self.deleted:
            return True
        self._get_user()

        if not self._works:
            self._connection = None
        return self._works

    def ask_amazon_for_account(self):
        """Get the account id for this key"""
        self._get_user(get_cached=True)
        return self.account_id

    def ask_amazon_for_username(self):
        """Get the username for this key"""
        self._get_user(get_cached=True)
        return self.username

    @property
    def create_epoch(self):
        """Use our create_epoch or ask amazon for it"""
        if self._create_epoch:
            return self._create_epoch
        elif self.works:
            self._create_epoch = self.ask_amazon_for_create_epoch()
            self.changed = True
            return self._create_epoch
        else:
            return 0

    @property
    def half_life(self):
        """Use our half_life or ask user for one"""
        if not self._half_life:
            self._half_life = ask_user_for_half_life(self.aws_access_key_id)
            self.changed = True
        return self._half_life

    def set_half_life(self, half_life):
        """Record a new half_life"""
        if half_life != self._half_life:
            self._half_life = half_life
            self.changed = True

    def create_new(self):
        """Create a new iam pair to use"""
        log.info("Creating a new key")
        response = self.connection.create_access_key(self.ask_amazon_for_username())["create_access_key_response"]["create_access_key_result"]["access_key"]
        iam_pair = IamPair(str(response["access_key_id"]), str(response["secret_access_key"]), create_epoch=self.amazon_date_to_epoch(response["create_date"]))

        # Give amazon time to think about this
        start = time.time()
        while time.time() - start < 5:
            if iam_pair.works:
                break
            time.sleep(1)

        return iam_pair

    def delete(self):
        """Delete this key pair from amazon"""
        return self.delete_access_key(self.aws_access_key_id)

    def delete_access_key(self, access_key):
        log.info("Deleting a key\taccess_key_id=%s", access_key)
        if access_key == self.aws_access_key_id:
            self.deleted = True
            self.changed = True
        return self.connection.delete_access_key(access_key)

    def find_other_access_keys(self):
        """Find all the access_keys for this user"""
        keys = self.connection.get_all_access_keys(self.ask_amazon_for_username())["list_access_keys_response"]["list_access_keys_result"]["access_key_metadata"]
        return [str(key["access_key_id"]) for key in keys]

    def ask_amazon_for_create_epoch(self):
        """Return our create_epoch"""
        username = self.ask_amazon_for_username()
        access_keys = self.connection.get_all_access_keys(username)["list_access_keys_response"]["list_access_keys_result"]["access_key_metadata"]
        create_date = [key for key in access_keys if key["access_key_id"] == self.connection.aws_access_key_id][0]['create_date']
        return self.amazon_date_to_epoch(create_date)

    def amazon_date_to_epoch(self, create_date):
        """Convert create_date from amazon into a create_epoch"""
        dt = boto.utils.parse_ts(create_date)
        return (dt - datetime.datetime(1970, 1, 1)).total_seconds()

    def _get_user(self, get_cached=False):
        """
        Get user details from this key and set
        self._working
        self.username
        self.account_id
        """
        if getattr(self, "_works", None) is False:
            # Already been here
            return

        try:
            if getattr(self, "_got_user", None) is None or not get_cached:
                details = self.connection.get_user()["get_user_response"]["get_user_result"]["user"]
                self._works = True
                self._got_user = True
                self.username = details["user_name"]

                # arn is arn:aws:iam::<account_id>:<other>
                self.account_id = details["arn"].split(":")[4]
        except boto.exception.BotoServerError as error:
            self._works = False
            if error.status == 403 and error.code in ("InvalidClientTokenId", "SignatureDoesNotMatch"):
                log.info("Found invalid access key and secret key combination\taccess_key=%s\terror_code=%s\terror=%s", self.aws_access_key_id, error.code, error.message)
                return
            raise

    def expired(self):
        """Say whether the age of this key is past twice it's half life"""
        return self.age > self.half_life * 2

    def past_half_life(self):
        """Say whether the age of this key is past it's half life"""
        return self.age > self.half_life

    @property
    def age(self):
        """Age is time since it's create_epoch"""
        return time.time() - self.create_epoch

class AmazonKey(object):
    """Represents the information and meta information required for amazon credentials"""
    def __init__(self, key_info, credential_info, crypto):
        self.crypto = crypto
        self.key_info = key_info
        self.credential_info = credential_info

    @property
    def changed(self):
        """Say whether this key has changed"""
        if self.iam_pair:
            return self.iam_pair.changed
        else:
            return False

    def unchanged(self):
        """Set the key as unchanged"""
        self._changed = False
        if self.iam_pair:
            self.iam_pair.changed = False

    @classmethod
    def using(kls, iam_pair, credential_info, crypto):
        """Create an AmazonKey from the provided details"""
        if not iam_pair.works:
            raise BadCredential()

        def verifier_maker(*args, **kwargs):
            kwargs["iam_pair"] = iam_pair
            instance = type("key", (AmazonKey, ), {"account": credential_info.account, "__init__": lambda s: None})()
            return kls.verifier_maker(instance, *args, **kwargs)

        fingerprinted = crypto.fingerprinted({"aws_access_key_id": iam_pair.aws_access_key_id, "aws_secret_access_key": iam_pair.aws_secret_access_key}, verifier_maker)
        key_info = {"fingerprints": fingerprinted, "create_epoch": iam_pair.create_epoch, "half_life": iam_pair.half_life}
        key = AmazonKey(key_info, credential_info, crypto)
        key._decrypted = [(iam_pair.aws_access_key_id, iam_pair.aws_secret_access_key)]
        return key

    def basic_validation(self):
        """Make sure the keys have basic requirements"""
        if "fingerprints" not in self.key_info:
            return "No fingerprints for this key"
        if not isinstance(self.fingerprints, dict):
            return "Fingerprints for this key are not a dictionary"
        if not self.crypto.decryptable(self.fingerprints):
            return "No private key can decrypt secrets"
        if any(not all(attr in value for attr in ("aws_access_key_id", "aws_secret_access_key", "__account_verifier__")) for value in self.fingerprints.values()):
            return "One or more of the fingeprints doesn't contain aws_access_key_id, aws_secret_access_key and __account_verifier__ values"

    @property
    def fingerprints(self):
        """Get our fingerprints from key_info"""
        if "fingerprints" not in self.key_info:
            self.key_info["fingerprints"] = {}
        return self.key_info["fingerprints"]

    def credentials(self):
        """Goes through our fingerprints and yields all our decryptable credentials as [aws_access_key_id, aws_secret_access_key]"""
        if getattr(self, "_decrypted", None):
            for key in self._decrypted:
                yield key
            return

        for decrypted in self.crypto.decrypt_by_fingerprint(self.fingerprints, self.verifier_maker):
            yield decrypted["aws_access_key_id"], decrypted["aws_secret_access_key"]

    @property
    def iam_pair(self):
        """Find the first verified iam pair"""
        if not getattr(self, "_iam_pair", None):
            for aws_access_key_id, aws_secret_access_key in self.credentials():
                self._iam_pair = IamPair(aws_access_key_id, aws_secret_access_key, self.key_info.get("create_epoch"), self.key_info.get("half_life"))
                break
        return getattr(self, "_iam_pair", None)

    @property
    def encrypted_values(self):
        """
        Return this key as a dictionary of {"fingerprints": {<fingerprint>: <info>, ...}, <other_options>}

        Where <info> is {"aws_access_key_id", "aws_secret_access_key"}

        and <other_options> includes {"create_epoch"}
        """
        def verifier_maker(*args, **kwargs):
            kwargs["iam_pair"] = self.iam_pair
            return self.verifier_maker(*args, **kwargs)

        fingerprints = self.crypto.fingerprinted({"aws_access_key_id": self.iam_pair.aws_access_key_id, "aws_secret_access_key": self.iam_pair.aws_secret_access_key}, verifier_maker)
        return {"fingerprints": fingerprints, "create_epoch": self.iam_pair.create_epoch, "half_life": self.iam_pair.half_life}

    def verifier_maker(self, encrypted, decrypted, iam_pair=None):
        """Return what our verifier should represent"""
        if iam_pair is not None:
            account = iam_pair.ask_amazon_for_account()
            username = iam_pair.ask_amazon_for_username()
        else:
            account = self.credential_info.get_account_id(self.crypto)
            username = self.credential_info.user

        value = "{0} || {1} || {2}".format(decrypted["aws_access_key_id"], account, username)
        information = {"account": account, "username": username, "access_key": decrypted["aws_access_key_id"]}
        return hashlib.sha1(value).hexdigest(), information

class AmazonKeys(object):
    """Collection of Amazon keys"""
    def __init__(self, keys, credential_info, crypto):
        if not keys:
            keys = []

        self.crypto = crypto
        self.credential_info = credential_info
        self.keys = [AmazonKey(key, credential_info, crypto) for key in keys]
        self._changed = False

    def __iter__(self):
        """Iterate through the keys"""
        return iter(self.keys)

    def __len__(self):
        """Return how many keys we have"""
        return len(self.keys)

    def add(self, key):
        """Add a key"""
        if not key.iam_pair or not key.iam_pair.works:
            raise BadCredential()

        if key.iam_pair.aws_access_key_id not in self.access_keys:
            self.keys.append(key)

    @property
    def changed(self):
        """Say whether there has been any changes"""
        return self._changed or any(key.changed for key in self.keys)

    def unchanged(self):
        """Reset changed on everything"""
        self._changed = False
        for key in self.keys:
            key.unchanged()

    @property
    def iam_pair(self):
        """Find the youngest iam pair"""
        keys = list(key for key in self.keys if key.iam_pair and key.iam_pair.works)
        if keys:
            return sorted(keys, key=lambda k: k.iam_pair.create_epoch, reverse=True)[0].iam_pair

    def basic_keys_validation(self):
        """Do some basic validation of our keys"""
        errors = []
        for index, key in enumerate(self.keys):
            nxt = key.basic_validation()
            if nxt:
                errors.append("key {0}: {1}".format(index+1, nxt))

        if errors:
            raise BadCredentialFile("Some of the keys were not valid", errors=errors)

    @property
    def encrypted_values(self):
        """Return our keys as a dictionary with encrypted values"""
        result = []
        for key in self.keys:
            if key.iam_pair and key.iam_pair.works:
                result.append(key.encrypted_values)
            else:
                log.info("Not saving invalid credentials\taccess_key=%s", list(key.credentials())[0][0])
        return result

    @property
    def access_keys(self):
        """Return all the access keys we know about"""
        for key in self.keys:
            iam_pair = key.iam_pair
            if iam_pair and iam_pair.works:
                yield iam_pair.aws_access_key_id

    def exports(self):
        """Return a list of (key, value) exports that would be necessary for the main iam_pair"""
        iam_pair = self.iam_pair
        if not iam_pair:
            raise NoCredentialsFound()

        return [
              ("AWS_ACCESS_KEY_ID", iam_pair.aws_access_key_id)
            , ("AWS_SECRET_ACCESS_KEY", iam_pair.aws_secret_access_key)
            ]

    def add_key(self, iam_pair):
        """Create a new key and add to our collection"""
        key = AmazonKey.using(iam_pair, self.credential_info, self.crypto)
        self.keys.append(key)
        self._changed = True
        return key

    def deal_with_unknown_key(self, access_key, valid_iam_pair):
        """Work out what to do with this key credo doesn't know about"""
        while True:
            quit_choice = "Quit"
            delete_choice = "Delete key"
            choice = ask_for_choice_or_new(
                  "action for dealing with an access_key credo doesn't know about ({0})".format(access_key)
                , [quit_choice, delete_choice]
                )

            if choice == quit_choice:
                raise UserQuit
            elif choice == delete_choice:
                valid_iam_pair.delete_access_key(access_key)
                return
            else:
                iam_pair = IamPair(access_key, choice)
                if iam_pair.works:
                    half_life = ask_user_for_half_life(iam_pair.aws_access_key_id)
                    iam_pair.set_half_life(half_life)
                    key = self.add_key(iam_pair)
                    if key:
                        return key
                else:
                    print >> sys.stderr, "The secret key you entered was not valid"

    def needs_rotation(self):
        """Say whether the current keys need any rotation"""
        return any(not key.iam_pair or key.iam_pair.past_half_life() or key.iam_pair.expired() for key in self.keys)

    def rotate(self):
        """Rotate the keys and return whether any of them changed"""
        while True:
            # Keep looking at the keys until we have no more surprises
            counts = {"created": 0, "deleted": 0, "removed": 0, "resolved": 0}
            usable = []
            to_remain = []
            for_deletion = []
            for_rotation = []

            known = []

            for key in self.keys:
                if not key.iam_pair or not key.iam_pair.works:
                    counts["removed"] += 1
                else:
                    usable.append(key.iam_pair)
                    known.append(key.iam_pair.aws_access_key_id)
                    if key.iam_pair.expired():
                        counts["deleted"] += 1
                        for_deletion.append(key.iam_pair)
                    elif key.iam_pair.past_half_life():
                        counts["created"] += 1
                        for_rotation.append(key.iam_pair)
                        to_remain.append(key)
                    else:
                        to_remain.append(key)

            extras = []
            if any(usable):
                others = usable[0].find_other_access_keys()
                for access_key in others:
                    if access_key not in known:
                        new_key = self.deal_with_unknown_key(access_key, usable[0])
                        counts["resolved"] += 1
                        if new_key:
                            extras.append(new_key)

            if not extras:
                break

        if not any(counts.values()):
            return False

        log.info("Rotation resulted in creating %s keys, deleting %s keys, removing %s stale keys and resolving %s unknown keys"
            , counts["created"], counts["deleted"], counts["removed"], counts["resolved"]
            )

        if not any(usable):
            # All the keys will be removed when we save
            # Up to code after that to complain there is nothing to create new keys with
            for key in for_deletion:
                key.delete()
        else:
            if for_deletion and to_remain:
                # Make sure we have room for creating a new key
                deleting = for_deletion.pop(0)
                deleting.delete()
                usable = [pair for pair in usable if pair is not deleting]

            if for_rotation or not to_remain:
                if len(to_remain) > 1:
                    oldest = sorted(to_remain, key=lambda k: k.iam_pair.create_epoch)[0]
                    oldest.delete()
                    usable = [pair for pair in usable if pair is not oldest]

                iam_pair = usable[0].create_new()
                iam_pair.set_half_life(ask_user_for_half_life(access_key))
                self.add_key(iam_pair)

            for key in for_deletion:
                # Delete the other keys marked for deletion
                key.delete()

        return True

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

