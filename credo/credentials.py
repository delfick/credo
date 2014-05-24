from credo.errors import BadCredentialFile, NoCredentialsFound, BadCredential

from boto.iam.connection import IAMConnection
import datetime
import hashlib
import logging
import copy
import time
import boto
import json
import os

log = logging.getLogger("credo.credentials")

class IamPair(object):
    def __init__(self, aws_access_key_id, aws_secret_access_key, account):
        self.account = account
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key

    @property
    def connection(self):
        """Get a connection for these keys"""
        if not getattr(self, "_connection", None):
            self._connection = IAMConnection(self.aws_access_key_id, self.aws_secret_access_key)
        return self._connection

    @property
    def works(self):
        """Says whether this key is valid enough to get iam informations"""
        self._get_user()
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
    def ask_amazon_for_create_epoch(self):
        """Return our create_epoch"""
        username = self.ask_amazon_for_username()
        access_keys = self.connection.get_all_access_keys(username)["list_access_keys_response"]["list_access_keys_result"]["access_key_metadata"]
        create_date = [key for key in access_keys if key["access_key_id"] == self.connection.aws_access_key_id][0]['create_date']
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
                log.info("Found invalid access key and secret key combination\taccess_key=%s", self.aws_access_key_id)
                return
            raise

class AmazonKey(object):
    """Represents the information and meta information required for amazon credentials"""
    def __init__(self, key_info, credential_info, crypto):
        self.pairs = {}
        self.crypto = crypto
        self.key_info = key_info
        self.credential_info = credential_info

    @classmethod
    def using(kls, aws_access_key_id, aws_secret_access_key, credential_info, crypto, create_epoch=None):
        """Create an AmazonKey from the provided details"""
        iam_pair = IamPair(aws_access_key_id, aws_secret_access_key, credential_info.account)
        if not iam_pair or not iam_pair.works:
            raise BadCredential()

        def verifier_maker(*args, **kwargs):
            kwargs["iam_pair"] = iam_pair
            instance = type("key", (AmazonKey, ), {"account": credential_info.account, "__init__": lambda s: None})()
            return kls.verifier_maker(instance, *args, **kwargs)

        fingerprinted = crypto.fingerprinted({"aws_access_key_id": aws_access_key_id, "aws_secret_access_key": aws_secret_access_key}, verifier_maker)
        key_info = {"fingerprints": fingerprinted, "create_epoch": create_epoch or time.time()}
        key = AmazonKey(key_info, credential_info, crypto)
        key._decrypted = [(aws_access_key_id, aws_secret_access_key)]
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
        """Find the first access_key that is working and matches our verifier"""
        if not getattr(self, "_iam_pair", None):
            for aws_access_key_id, aws_secret_access_key in self.credentials():
                ident = "{0}{1}".format(aws_access_key_id, aws_secret_access_key)
                if ident in self.pairs:
                    pair = self.pairs[ident]
                else:
                    pair = IamPair(aws_access_key_id, aws_secret_access_key, self.credential_info.account)
                    self.pairs[ident] = pair

                if pair.works:
                    self._iam_pair = pair
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

        create_epoch = self.iam_pair.ask_amazon_for_create_epoch
        fingerprints = self.crypto.fingerprinted({"aws_access_key_id": self.iam_pair.aws_access_key_id, "aws_secret_access_key": self.iam_pair.aws_secret_access_key}, verifier_maker)
        return {"fingerprints": fingerprints, "create_epoch": create_epoch}

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

        self.keys = [AmazonKey(key, credential_info, crypto) for key in keys]

    def add(self, key):
        """Add a key"""
        if not key.iam_pair or not key.iam_pair.works:
            raise BadCredential()

        if key.iam_pair.aws_access_key_id not in self.access_keys:
            self.keys.append(key)

    @property
    def iam_pair(self):
        """Find the youngest iam pair"""
        for key in self.keys:
            if key.iam_pair:
                return key.iam_pair

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
    def current(self):
        """Find our current working keys"""
        if getattr(self, "_current", None):
            if not self._current.works:
                self._current = None

        if not getattr(self, "_current", None):
            self._current = self.rotate()

        return self._current

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
            if iam_pair:
                yield iam_pair.aws_access_key_id

class AmazonCredentials(object):
    """Knows about amazon credential files"""

    def __init__(self, typ, credential_info, contents, crypto):
        self.typ = typ
        self.crypto = crypto
        self.contents = contents
        self.credential_info = credential_info

        self.keys = AmazonKeys(self.contents.get("keys"), self.credential_info, crypto)

    @property
    def location(self):
        return self.credential_info.location

    def add_key(self, aws_access_key_id, aws_secret_access_key):
        """Add a key"""
        self.keys.add(AmazonKey.using(aws_access_key_id, aws_secret_access_key, self.credential_info, self.crypto))

    @property
    def encrypted_values(self):
        """Return _values as a dictionary with some encrypted values"""
        contents = copy.deepcopy(self.contents)
        contents["keys"] = self.keys.encrypted_values
        return contents

    def save(self):
        """Write our values to our json file"""
        dirname = os.path.dirname(self.location)
        if not os.path.exists(dirname):
            try:
                os.makedirs(dirname)
            except OSError as err:
                raise BadCredentialFile("Can't create parent directory", err=err)

        if not os.access(dirname, os.W_OK):
            raise BadCredentialFile("Don't have write permissions to parent directory", location=self.location)

        try:
            vals = self.encrypted_values
        except UnicodeDecodeError as err:
            raise BadCredentialFile("Can't get encrypted values for the credentials file!", err=err, location=self.location)

        try:
            contents = json.dumps(vals, indent=4)
        except ValueError as err:
            raise BadCredentialFile("Can't create credentials as json", err=err, location=self.location)

        try:
            with open(self.location, "w") as fle:
                log.info("Saving credentials for %s|%s|%s with access_keys %s", self.credential_info.repo, self.credential_info.account, self.credential_info.user, list(self.keys.access_keys))
                fle.write(contents)
        except OSError as err:
            raise BadCredentialFile("Can't write to the credentials file", err=err, location=self.location)

    def rotate(self):
        """Rotate the credentials"""
        counts = {"added": 0, "deleted": 0}
        self.save()
        return counts

    def shell_exports(self):
        """Return list of (key, val) exports we want to have in the shell"""
        iam_pair = self.keys.iam_pair
        if not iam_pair:
            raise NoCredentialsFound()

        return [
              ("AWS_ACCESS_KEY_ID", iam_pair.aws_access_key_id)
            , ("AWS_SECRET_ACCESS_KEY", iam_pair.aws_secret_access_key)
            , ("CREDULOUS_CURRENT_REPO", self.credential_info.repo)
            , ("CREDULOUS_CURRENT_ACCOUNT", self.credential_info.account)
            , ("CREDULOUS_CURRENT_USER", self.credential_info.user)
            ]

    def as_string(self):
        """Return information about credentials as a string"""
        return "Credentials!"

