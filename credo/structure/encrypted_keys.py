from credo.helper import KeysFile

class Unset(object):
    """Used to say unset an environment variable"""

class EncryptedKeys(object):
    """Collection of environment variables"""
    def __init__(self, location, credential_path):
        self.location = location
        self.credential_path = credential_path

    def add(self, key, value):
        """Add a key"""
        raise NotImplementedError()

    def unchanged(self):
        """Reset changed on everything"""
        raise NotImplementedError()

    @property
    def encrypted_values(self):
        """Return our values as a dictionary with encrypted values"""
        raise NotImplementedError()

    def make_keys(self, contents):
        """Get us our keys from the contents of the file"""
        raise NotImplementedError()

    def shell_exports(self):
        """Return list of (key, val) exports we want to have in the shell"""
        raise NotImplementedError()

    def as_string(self):
        """Return information about keys as a string"""
        raise NotImplementedError()

    def default_keys_type(self):
        """Return the default key type (i.e. list, dict)"""
        raise NotImplementedError()

    def default_keys_type_name(self):
        """Return the default key type name (i.e. amazon, environment)"""
        raise NotImplementedError()

    @property
    def crypto(self):
        """Proxy credential_path"""
        return self.credential_path.crypto

    def load(self):
        """Just return the contents"""
        return self.contents

    def save(self, force=False):
        """Save our credentials to file"""
        self.contents.save(self.location, self)

    def __iter__(self):
        """Iterate through the environment variables"""
        return iter(self.keys.items())

    def __len__(self):
        """Return how many environment variables we have"""
        return len(self.keys)

    @property
    def changed(self):
        """Say whether there has been any changes"""
        return self._changed

    @property
    def contents(self):
        """Get us the contents"""
        if not hasattr(self, "_contents"):
            self._contents = KeysFile(default_keys_type=self.default_keys_type, default_keys_type_name=self.default_keys_type_name)
            self._contents.load(self.location)
        return self._contents

    @property
    def keys(self):
        """Get us some keys"""
        if not hasattr(self, "_keys"):
            self._keys = self.make_keys(self.contents)
        return self._keys

