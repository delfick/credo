from credo.errors import NoValueEntered, BadKeyFile
from credo.asker import ask_for_choice_or_new

import logging
import copy
import json
import os

log = logging.getLogger("credo.helper")

def record_non_dicts(subject, memo):
    """Find all the things in subject that are not string or dicts and fill memo with {id(thing): thing}"""
    for key, val in subject.items():
        if not isinstance(val, dict) and not isinstance(val, basestring):
            memo[id(val)] = val

        elif isinstance(val, dict):
            record_non_dicts(val, memo)

def copy_dict_structure(structure):
    """Copy the structure of a dictionary without modifying any of the contents"""
    memo = {}
    record_non_dicts(structure, memo)
    return copy.deepcopy(structure, memo=memo)

def print_list_of_tuples(lst, prefix):
    """Helper for printing out a list of tuples"""
    if any(val for _, val in lst):
        print "{0}: {1}".format(prefix, " | ".join("{0}={1}".format(key, val) for key, val in lst if val))

def make_export_commands(exports, no_transform=False):
    for key, val in exports:
        if val == "CREDO_UNSET" and not no_transform:
            yield "unset {0}".format(key)
        else:
            yield "export {0}=\"{1}\"".format(key, val.replace("\\\"", "\"").replace("\"", "\\\""))

class SignedValueFile(object):
    """Knows how to store a value in a file with a signature"""
    def __init__(self, location, crypto, extra_info):
        self.crypto = crypto
        self.location = location
        self.extra_info = extra_info

    def retrieve(self, name, question, suggestions):
        """Return the value in our signed file"""
        value = self.recorded_value()
        if not value:
            value = self.ask_for_value(name, question, suggestions)
            fingerprint, signature = self.crypto.create_signature(self.signature_value(value))

            dirname = os.path.dirname(self.location)
            if not os.path.exists(dirname):
                os.makedirs(dirname)

            with open(self.location, "w") as fle:
                fle.write("{0},{1},{2}".format(value, fingerprint, signature))
            return value, True
        return value, False

    def signature_value(self, value):
        """Return string for signing in the signed value file"""
        infos = "|".join(str(thing) for _, thing in sorted(self.extra_info.items()))
        return "{0}|{1}".format(infos, value)

    def recorded_value(self):
        """Read our current signed value"""
        incorrect = False
        value = None

        if os.path.exists(self.location) and os.access(self.location, os.R_OK):
            with open(self.location) as fle:
                contents = fle.read().strip().split("\n")[0]

            if contents.count(',') != 2:
                incorrect = True
            else:
                value, fingerprint, signature = contents.split(',')
                if not self.crypto.is_signature_valid(self.signature_value(value), fingerprint, signature):
                    incorrect = True

        if incorrect:
            log.error("Was something corrupt about the value file\tlocation=%s", self.location)
            return

        return value

    def ask_for_value(self, name, question, suggestions):
        """Get a value from the user"""
        choices = ["Quit"]

        if callable(suggestions):
            suggestions = suggestions()

        suggestion_strings = []
        if suggestions:
            for suggestion in suggestions:
                suggestion_string = str(suggestion)
                suggestion_strings.append(suggestion_string)
                choices.insert(0, suggestion_string)

        choice = ask_for_choice_or_new(question, choices)

        if choice == "Quit":
            raise NoValueEntered()
        else:
            value = choice

        return value

class KeysFile(object):
    """Understands how to load and save to a keys file"""
    def __init__(self, default_keys_type=list, default_keys_type_name="amazon"):
        self.default_keys_type = default_keys_type
        self.default_keys_type_name = default_keys_type_name

    def read_file(self, location):
        """Read in our location as a json file"""
        if not os.path.exists(location):
            raise BadKeyFile("Doesn't exist", location=location)
        if not os.access(location, os.R_OK):
            raise BadKeyFile("Don't have read permissions", location=location)

        if os.stat(location).st_size == 0:
            return {}

        try:
            return json.load(open(location))
        except ValueError as err:
            raise BadKeyFile("Keys file not valid json", location=location, error=err)

    def load(self, location):
        """Load the keys from our keys file"""
        contents = {"keys": self.default_keys_type(), "type": self.default_keys_type_name}
        if os.path.exists(location):
            contents = self.read_file(location)

        if not isinstance(contents.get("keys", []), self.default_keys_type):
            raise BadKeyFile("Keys file keys are not correct", expected_type=self.default_keys_type, got_type=type(contents["keys"]))

        self.contents = contents
        self.typ = self.contents.get("type", self.default_keys_type_name)
        self.keys = self.contents.get("keys", self.default_keys_type())

    def save(self, location, keys, **info):
        """Save the provided keys to this location"""
        dirname = os.path.dirname(location)
        if not os.path.exists(dirname):
            try:
                os.makedirs(dirname)
            except OSError as err:
                raise BadKeyFile("Can't create parent directory", err=err)

        if not os.access(dirname, os.W_OK):
            raise BadKeyFile("Don't have write permissions to parent directory", location=location)

        try:
            key_vals, access_keys = keys.encrypted_values
        except UnicodeDecodeError as err:
            raise BadKeyFile("Can't get encrypted values for the keys file!", err=err, location=location)

        try:
            vals = {"type": keys.type, "keys": key_vals}
            contents = json.dumps(vals, indent=4)
        except ValueError as err:
            raise BadKeyFile("Can't create keys as json", err=err, location=location)

        try:
            with open(location, "w") as fle:
                info_str = ""
                if info:
                    info_str = "\t{0}".format("\t".join("{0}={1}".format(key, val) for key, val in info.items()))
                log.info("Saving keys to %s%s", location, info_str)
                fle.write(contents)
        except OSError as err:
            raise BadKeyFile("Can't write to the keys file", err=err, location=location)

