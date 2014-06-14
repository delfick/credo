from credo.asker import ask_user_for_half_life

from boto.iam.connection import IAMConnection
import datetime
import logging
import time
import boto
import os

log = logging.getLogger("credo.amazon")

class IamPair(object):
    def __init__(self, aws_access_key_id, aws_secret_access_key, create_epoch=None, half_life=None):
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key

        self._half_life = half_life
        self._create_epoch = create_epoch
        self._changed = False
        self.deleted = False

    @property
    def changed(self):
        """Get us value of _changed"""
        return self._changed

    def unchanged(self):
        """Set _changed to False"""
        self._changed = False

    def mark_as_invalid(self):
        """Mark the key as invalid"""
        self.invalidated = True

    @classmethod
    def from_environment(kls, create_epoch=None, half_life=None):
        """Get an IAMPair from our environment variables"""
        pair = kls(os.environ["AWS_ACCESS_KEY_ID"], os.environ["AWS_SECRET_ACCESS_KEY"], create_epoch, half_life)
        pair._connection = IAMConnection()
        return pair

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
        if getattr(self, "_works", None) is False:
            return self._works

        get_cached = hasattr(self, "_last_asked") and (time.time() - self._last_asked) < 6
        self._last_asked = time.time()
        self._get_user(get_cached=get_cached)

        return self._works

    def wait_till_works(self):
        """Wait till this iam pair works"""
        # Give amazon time to think about this
        start = time.time()
        while time.time() - start < 20:
            self._get_user(quiet=True)
            if self._works:
                break
            time.sleep(2)

    def ask_amazon_for_account(self):
        """Get the account id for this key"""
        self._get_user(get_cached=True)
        return getattr(self, "account_id", None)

    def ask_amazon_for_account_aliases(self):
        """Get the account aliases for this key"""
        self._get_user(get_cached=True)
        return getattr(self, "account_aliases", None)

    def ask_amazon_for_username(self):
        """Get the username for this key"""
        self._get_user(get_cached=True)
        return getattr(self, "username", None)

    @property
    def create_epoch(self):
        """Use our create_epoch or ask amazon for it"""
        if self._create_epoch:
            return self._create_epoch
        elif self.works:
            self._create_epoch = self.ask_amazon_for_create_epoch()
            self._changed = True
            return self._create_epoch
        else:
            return 0

    @property
    def half_life(self):
        """Use our half_life or ask user for one"""
        if not self._half_life:
            self._half_life = ask_user_for_half_life(self.aws_access_key_id)
            self._changed = True
        return self._half_life

    def set_half_life(self, half_life):
        """Record a new half_life"""
        if half_life != self._half_life:
            self._half_life = half_life
            self._changed = True

    def create_new(self):
        """Create a new iam pair to use"""
        log.info("Creating a new key")
        response = self.connection.create_access_key(self.ask_amazon_for_username())["create_access_key_response"]["create_access_key_result"]["access_key"]
        log.info("Created %s", response["access_key_id"])
        iam_pair = IamPair(str(response["access_key_id"]), str(response["secret_access_key"]), create_epoch=self.amazon_date_to_epoch(response["create_date"]))
        iam_pair.wait_till_works()
        return iam_pair

    def delete(self):
        """Delete this key pair from amazon"""
        return self.delete_access_key(self.aws_access_key_id)

    def delete_access_key(self, access_key):
        log.info("Deleting a key\taccess_key_id=%s", access_key)
        if access_key == self.aws_access_key_id:
            self.deleted = True
            self._changed = True
        return self.connection.delete_access_key(access_key)

    def find_other_access_keys(self):
        """Find all the access_keys for this user"""
        keys = self.connection.get_all_access_keys(self.ask_amazon_for_username())["list_access_keys_response"]["list_access_keys_result"]["access_key_metadata"]
        return [str(key["access_key_id"]) for key in keys]

    def is_root_credentials(self):
        """
        Return whether these credentials are possibly root credentials
        I.e. Amazon say they don't exist and it has the same name as an account alias
        """
        username = self.ask_amazon_for_username()
        try:
            self.connection.get_all_access_keys(username)
        except boto.exception.BotoServerError as error:
            if error.status == 404 and error.code == "NoSuchEntity":
                if username in self.ask_amazon_for_account_aliases():
                    return True
            else:
                raise
        return False

    def ask_amazon_for_create_epoch(self):
        """Return our create_epoch"""
        if self.is_root_credentials():
            result = self.connection.get_response('ListAccessKeys', {}, list_marker='AccessKeyMetadata')
        else:
            username = self.ask_amazon_for_username()
            result = self.connection.get_all_access_keys(username)

        access_keys = result["list_access_keys_response"]["list_access_keys_result"]["access_key_metadata"]
        create_date = [key for key in access_keys if key["access_key_id"] == self.connection.aws_access_key_id][0]['create_date']
        return self.amazon_date_to_epoch(create_date)

    def amazon_date_to_epoch(self, create_date):
        """Convert create_date from amazon into a create_epoch"""
        dt = boto.utils.parse_ts(create_date)
        return (dt - datetime.datetime(1970, 1, 1)).total_seconds()

    def _get_user(self, get_cached=False, quiet=False):
        """
        Get user details from this key and set
        self._working
        self.username
        self.account_id
        """
        try:
            if getattr(self, "_got_user", None) is None or not get_cached:
                log.info("Asking amazon for account id and username\taccess_key=%s", self.aws_access_key_id)
                details = self.connection.get_user()["get_user_response"]["get_user_result"]["user"]
                aliases = self.connection.get_account_alias()["list_account_aliases_response"]["list_account_aliases_result"]["account_aliases"]
                self._invalid = False
                self._works = True
                self._got_user = True
                self.username = details["user_name"]

                # arn is arn:aws:iam::<account_id>:<other>
                self.account_id = details["arn"].split(":")[4]
                self.account_aliases = aliases
        except boto.exception.BotoServerError as error:
            self._works = False
            self._got_user = False
            self._connection = None
            if error.status == 403 and error.code in ("InvalidClientTokenId", "SignatureDoesNotMatch"):
                self._invalid = True
                if not quiet:
                    log.info("Found invalid access key and secret key combination\taccess_key=%s\terror_code=%s\terror=%s", self.aws_access_key_id, error.code, error.message)
                return
            raise

    def expired(self):
        """Say whether the age of this key is past twice it's half life or marked as invalid"""
        return getattr(self, "invalidated", False) or self.age > self.half_life * 2

    def past_half_life(self):
        """Say whether the age of this key is past it's half life"""
        return self.age > self.half_life

    @property
    def age(self):
        """Age is time since it's create_epoch"""
        return time.time() - self.create_epoch

