from credo.errors import CredoError, BadCredentialFile
from credo.asker import ask_for_choice_or_new

from boto.iam.connection import IAMConnection
import datetime
import logging
import boto
import time

log = logging.getLogger("credo.rotator")

class Rotator(object):
    """Knows how to rotate aws credentials"""
    def rotate(self, values, user, use_environment_for_rotation_creds=True, half_life=3600, access_key=None, secret_key=None):
        """
        Rotate the values

        Assume values is {"key1": <values>, "key2": <values}

        Return new (values, current) where values is the rotated keys and current is the key <values> to use
        """
        counts = {"deleted": 0, "created": 0}

        targets = dict([(key, value) for key, value in values.items() if "aws_access_key_id" in value])
        if len(targets) is 1:
            targets["key1"] = targets.items()[0][1]
            targets["key2"] = {}

        iam_access_key, iam_secret_key = self.get_creds_for_rotation(targets, access_key, secret_key, use_environment_for_rotation_creds=use_environment_for_rotation_creds)
        iam_connection = IAMConnection(iam_access_key, iam_secret_key)
        counts["deleted"] += self.fill_out(user, targets, iam_connection, half_life, access_key, secret_key)

        expired = []
        def expire(key, value, multiplier=2):
            """Expire a key or mark as expired if necessary"""
            if self.determine_if_expired(value, multiplier=multiplier):
                if value.get("aws_access_key_id") != iam_access_key:
                    self.expire(user, value.get("aws_access_key_id"), iam_connection)
                    counts["deleted"] += 1
                else:
                    expired.append(value)
                targets[key] = {}

        # Find keys that should be expired
        for key, value in targets.items():
            expire(key, value)

        # Expire second key if first is past half life
        if any(targets.values()):
            (ck, current), (ok, other) = self.as_sorted(targets.items())
            if current and other and self.determine_if_expired(current, multiplier=1):
                expire(ok, other, multiplier=1)

        # Now we create new keys
        empty_slots = [(key, value) for key, value in targets.items() if not value]
        if not any(targets.values()) or empty_slots:
            if empty_slots:
                key, value = empty_slots[0]
            else:
                key, value = "key1", {}

            if access_key and secret_key:
                targets[key] = self.use_new_key(value, user, access_key, secret_key, half_life=half_life)
            else:
                targets[key] = self.make_new_key(value, user, half_life=half_life, iam_connection=iam_connection)
                counts["created"] += 1

        # And expire what's remaining
        for value in expired:
            if "aws_access_key_id" in value:
                self.expire(user, value["aws_access_key_id"], iam_connection)
                counts["deleted"] += 1

        self.normalise_keys(targets)
        return targets, self.as_sorted(targets.items())[-1][1], counts

    def as_sorted(self, values):
        """Return keys sorted in ascending create time"""
        return sorted(values, key = lambda (k,v): v.get("create_epoch", time.time()))

    def determine_if_expired(self, value, multiplier=2):
        """Determine if key is past half_life by a particular multiplier"""
        created = value.get("create_epoch", time.time())
        lifetime = value.get("half_life", 3600) * multiplier

        now = time.time()
        return (now - created) > lifetime

    def expire(self, user, access_key, iam_connection):
        """Expire the provided keys"""
        iam_connection.delete_access_key(access_key, user)

    def make_new_key(self, extra_options, user, half_life, iam_connection):
        """Make us a new key and return the result"""
        result = {}
        result.update(extra_options)
        result["half_life"] = half_life

        result = iam_connection.create_access_key(user)
        info = result["create_access_key_response"]["create_access_key_result"]["access_key"]
        create_epoch = self.create_date_to_epoch(info["create_date"])

        return self.use_new_key({}, user, info["access_key_id"], info["secret_access_key"], half_life=half_life, create_epoch=create_epoch)

    def get_creds_for_rotation(self, values, access_key=None, secret_key=None, use_environment_for_rotation_creds=True):
        """Knows how to get a connection to aws iam"""
        if not use_environment_for_rotation_creds:
            return None, None
        else:
            if access_key and secret_key:
                return access_key, secret_key
            else:
                if not any("aws_access_key_id" in value and "aws_secret_access_key" in value for value in values.values()):
                    raise CredoError("Don't have any keys to use to ask amazon for rotating keys :(")

                current = self.as_sorted([(key, value) for key, value in values.items() if value])[-1][1]
                return current["aws_access_key_id"], current["aws_secret_access_key"]

    def use_new_key(self, extra_options, user, access_key, secret_key, half_life, create_epoch=None):
        """Return us the dictionary representing a new aws credentials"""
        result = {}
        result.update(extra_options)
        result["create_epoch"] = create_epoch or time.time()
        result["half_life"] = half_life
        result["aws_access_key_id"] = access_key
        result["aws_secret_access_key"] = secret_key
        return result

    def normalise_keys(self, targets):
        """Make sure the keys have create_epoch times"""
        for value in targets.values():
            if "aws_access_key_id" in value:
                if "create_epoch" not in value:
                    value["create_epoch"] = time.time()

    def fill_out(self, user, targets, iam_connection, half_life=3600, access_key=None, secret_key=None):
        """Fill out our targets with what keys actually exist and return how many are deleted"""
        if len([val for val in targets.values() if val]) is 1:
            # Make sure amazon does indeed only have one credential
            access_keys = iam_connection.get_all_access_keys(user)
            keys = access_keys["list_access_keys_response"]["list_access_keys_result"]["access_key_metadata"]
            aws_access_keys = dict([(value['access_key_id'], value) for value in keys])
            known_access_keys = dict([(value['aws_access_key_id'], value) for value in targets.values() if 'aws_access_key_id' in value])

            missing = set(aws_access_keys.keys()) - set(known_access_keys)
            extranous = set(known_access_keys) - set(aws_access_keys)
            if extranous:
                log.info("Ignoring keys amazon no longer knows about: %s", list(extranous))
                for key, value in targets.items():
                    if value.get("aws_access_key_id") in extranous:
                        del targets[key]

            if missing:
                for missed in missing:
                    if missed != access_key:
                        aws_cred = aws_access_keys[missed]
                        val = ask_for_choice_or_new("How should we deal with credential amazon has but credo doesn't know about? ({0})".format(missed), ("Delete access key", "quit"))
                        if val == "quit":
                            raise BadCredentialFile("User quit when deciding what to do with missing credentials")
                        elif val == "Delete access key":
                            self.expire(user, missed, iam_connection)
                            return 1
                        else:
                            current_key = [key for key, value in targets.items() if value.get("aws_access_key_id") != aws_cred.get("access_key_id")][0]
                            key = "key2" if current_key == "key1" else "key1"
                            create_epoch = self.create_date_to_epoch(aws_cred["create_date"])
                            targets[key] = self.use_new_key({}, user, aws_cred["access_key_id"], val, create_epoch=create_epoch, half_life=half_life)

        return 0

    def create_date_to_epoch(self, create_date):
        """Get a create_date string and turn it into an epoch"""
        dt = boto.utils.parse_ts(create_date)
        return (dt - datetime.datetime(1970, 1, 1)).total_seconds()

