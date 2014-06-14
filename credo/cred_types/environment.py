import logging
import os

log = logging.getLogger("credo.cred_types.environment")

class Unset(object):
    """Used to say unset an environment variable"""

class Environment(object):
    """Collection of environment variables"""
    type = "environment"

    def __init__(self, values, credential_path):
        if not values:
            values = {}

        self.credential_path = credential_path
        self._changed = False

    @property
    def crypto(self):
        """Proxy credential_path"""
        return self.credential_path.crypto

    def __iter__(self):
        """Iterate through the environment variables"""
        return iter(self.values.items())

    def __len__(self):
        """Return how many environment variables we have"""
        return len(self.values)

    def add(self, key, value):
        """Add a key"""
        Empty = type("Empty", (object, ), {})
        if self.values.get(key, Empty) != value:
            self._changed = True
            self.values[key] = value

    @property
    def changed(self):
        """Say whether there has been any changes"""
        return self._changed

    def unchanged(self):
        """Reset changed on everything"""
        self._changed = False

    @property
    def encrypted_values(self):
        """Return our values as a dictionary with encrypted values"""
        result = []
        log.info("Making encrypted values for environment variables")
        fingerprints = self.crypto.fingerprinted(self.values())
        result = {"fingerprints": fingerprints}
        return result, self.values.keys()

    def exports(self):
        """Return a list of (key, value) exports that would be necessary for the main iam_pair"""
        unsetters = {}
        for key in self.values:
            name = "CREDO_UNSET_{0}".format(key)
            if key not in os.environ:
                unsetters[name] = Unset
            else:
                unsetters[name] = os.environ[key]

        return sorted(self.values.items()) + sorted(unsetters.items())

