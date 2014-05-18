from credo.errors import BadCredentialFile, NoCredentialsFound

from boto.iam.connection import IAMConnection
import hashlib
import logging
import copy
import time
import json
import os

log = logging.getLogger("credo.credentials")

class MemoizedProperty(object):
    """A property that memoizes it's result"""
    def __init__(self, creator):
        self.creator = creator

    def __get__(self, obj=None, owner=None):
        """Return the memoized property or create new property"""
        if not getattr(self, "_memoized", None):
            self._memoized = self.creator(obj)
        return self._memoized

    def __delete__(self, obj=None):
        """Unset our memoized value"""
        self._memoized = None

class IamPair(object):
    def __init__(self, aws_access_key_id, aws_secret_access_key, account):
        self.account = account
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key

    @MemoizedProperty
    def connection(self):
        """Get a connection for these keys"""
        return IAMConnection(self.aws_access_key_id, self.aws_secret_access_key)

    @property
    def works(self):
        """Says whether this key works and is active"""
        return self.exists and self.active

    @property
    def exists(self):
        """Says that this key hasn't been deleted"""
        self.connection.get_account_summary()
        return True

    @property
    def active(self):
        """Says that this key hasn't been made inactive"""
        self.connection.get_account_summary()
        return True

    @property
    def create_epoch(self):
        """Return our create_epoch"""
        return time.time()

class AmazonKey(object):
    """Represents the information and meta information required for amazon credentials"""
    def __init__(self, key_info, account, crypto):
        self.crypto = crypto
        self.account = account
        self.key_info = key_info

    @classmethod
    def using(kls, aws_access_key_id, aws_secret_access_key, account, crypto, create_epoch=None):
        """Create an AmazonKey from the provided details"""
        verifier_maker = lambda *args, **kwargs: kls.verifier_maker(type("key", (AmazonKey, ), {"account": account, "__init__": lambda s: None})(), *args, **kwargs)
        fingerprinted = crypto.fingerprinted({"aws_access_key_id": aws_access_key_id, "aws_secret_access_key": aws_secret_access_key}, verifier_maker)
        key_info = {"fingerprints": fingerprinted, "create_epoch": create_epoch or time.time()}
        return AmazonKey(key_info, account, crypto)

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
        for decrypted in self.crypto.decrypt_by_fingerprint(self.fingerprints, self.verifier_maker):
            yield decrypted["aws_access_key_id"], decrypted["aws_secret_access_key"]

    @MemoizedProperty
    def iam_pair(self):
        """Find the first access_key that is working and matches our verifier"""
        for aws_access_key_id, aws_secret_access_key in self.credentials():
            pair = IamPair(aws_access_key_id, aws_secret_access_key, self.account)
            if pair.works:
                return pair

    @property
    def encrypted_values(self):
        """
        Return this key as a dictionary of {"fingerprints": {<fingerprint>: <info>, ...}, <other_options>}

        Where <info> is {"aws_access_key_id", "aws_secret_access_key"}

        and <other_options> includes {"create_epoch"}
        """
        create_epoch = self.iam_pair.create_epoch
        fingerprints = self.crypto.fingerprinted({"aws_access_key_id": self.iam_pair.aws_access_key_id, "aws_secret_access_key": self.iam_pair.aws_secret_access_key}, self.verifier_maker)
        return {"fingerprints": fingerprints, "create_epoch": create_epoch}

    def verifier_maker(self, encrypted, decrypted):
        """Return what our verifier should represent"""
        return hashlib.sha1("{0}||{1}".format(self.account, encrypted["aws_access_key_id"])).hexdigest()

class AmazonKeys(object):
    """Collection of Amazon keys"""
    def __init__(self, keys, account, crypto):
        if not keys:
            keys = []

        self.account = account
        self.keys = [AmazonKey(key, account, crypto) for key in keys]

    def add(self, key):
        """Add a key"""
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
        return [key.encrypted_values for key in self.keys]

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

        self.keys = AmazonKeys(self.contents.get("keys"), self.credential_info.account, crypto)

    @property
    def location(self):
        return self.credential_info.location

    def add_key(self, aws_access_key_id, aws_secret_access_key):
        """Add a key"""
        self.keys.add(AmazonKey.using(aws_access_key_id, aws_secret_access_key, self.credential_info.account, self.crypto))

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
        self.save()
        return {}

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

