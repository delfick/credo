from credo.structure.encrypted_keys import EncryptedKeys
from credo.errors import BadKeyFile, CredoError
import logging
import os

log = logging.getLogger("credo.cred_types.environment")

class EnvironmentFile(EncryptedKeys):
    """Collection of environment variables"""
    def __init__(self, location):
        self.location = location

    @classmethod
    def shell_exports_from(self, location, logger):
        """Return the shell exports from this environment file and log errors"""
        if not os.path.exists(location):
            return []

        keys = EnvironmentFile(location)
        try:
            keys.load()
        except CredoError as error:
            log.warning("Failed to load environment variables\tlocation=%s\terror_type=%s\terror=%s", location, error.__class__.__name__, error)
            return []

        return keys.shell_exports()

    @property
    def type(self):
        """This needs to be set"""
        return "environment"

    def add(self, key, value):
        """Add a key"""
        Empty = type("Empty", (object, ), {})
        if self.keys.get(key, Empty) != value:
            self._changed = True
            self.keys[key] = value

    def unchanged(self):
        """Reset changed on everything"""
        self._changed = False

    @property
    def encrypted_values(self):
        """Return our values as a dictionary with encrypted values"""
        result = []
        log.info("Making encrypted values for environment variables")
        fingerprints = self.crypto.fingerprinted(self.keys)
        result = {"fingerprints": fingerprints}
        return result, self.values.keys()

    def make_keys(self, contents):
        """Get us our keys from the contents of the file"""
        if contents.typ != self.type:
            raise BadKeyFile("Unknown type", type=contents.get("type"))
        return contents.keys

    def shell_exports(self):
        """Return list of (key, val) exports we want to have in the shell"""
        unsetters = {}
        for key in self.values:
            name = "CREDO_UNSET_{0}".format(key)
            if key not in os.environ:
                unsetters[name] = "CREDO_UNSET"
            else:
                unsetters[name] = os.environ[key]

        return sorted(self.values.items()) + sorted(unsetters.items())

    def default_keys_type(self):
        """Empty keys is a dict"""
        return list

    def default_keys_type_name(self):
        """Assume type is environment"""
        return "environment"

    def as_string(self):
        """Return information about keys as a string"""
        return "Environment vars! {0}".format(", ".join(self))

