from credo.errors import BadKeyFile, CredoError, UserQuit
from credo.structure.encrypted_keys import EncryptedKeys
from credo.asker import ask_for_choice

import logging
import os

log = logging.getLogger("credo.cred_types.environment")

class EnvironmentMixin:
    @property
    def environment_location(self):
        """Where we should store environment vars"""
        return os.path.join(self.location, "env.json")

    def get_env_file(self, crypto):
        """Get us an EnvironmentFile object"""
        if not hasattr(self, "_env_file_cache"):
            self._env_file_cache = {}
        return EnvironmentFile.find_env(self.environment_location, crypto, self, cache=self._env_file_cache)

    def add_env(self, env, crypto):
        """Add another environment variable"""
        keys = self.get_env_file(crypto)

        for key, val in env:
            keys.add(key, val)

        keys.save()

    def remove_env(self, env, crypto):
        """Remove an environment variable"""
        keys = self.get_env_file(crypto)

        for key in env:
            keys.remove(key)

        keys.save()

    def shell_exports(self):
        """Get us some environment exports if there are any"""
        keys, error = EnvironmentFile.loaded_file_from(self.environment_location, self.crypto, self)
        if not keys:
            keys = EnvironmentFile(self.environment_location, self.crypto, self)

        return keys.shell_exports()

class EnvironmentFile(EncryptedKeys):
    """Collection of environment variables"""
    def __init__(self, location, crypto, owner):
        self.owner = owner
        self.crypto = crypto
        self.location = location
        self._changed = False

    @property
    def changed(self):
        return self._changed

    def unchanged(self):
        """Set as not changed"""
        self._changed = False

    @classmethod
    def loaded_file_from(kls, location, crypto, owner):
        """Return the shell exports from this environment file and log errors"""
        if not os.path.exists(location):
            return None, False

        keys = EnvironmentFile(location, crypto, owner)
        try:
            keys.load()
        except CredoError as error:
            log.warning("Failed to load environment variables\tlocation=%s\terror_type=%s\terror=%s", location, error.__class__.__name__, error)
            return None, error

        return keys, None

    @classmethod
    def find_env(kls, location, crypto, owner, cache=None):
        """Add environment variables to our environment file"""
        if cache and location in cache:
            return cache[location]

        while True:
            keys, error = EnvironmentFile.loaded_file_from(location, crypto, owner)
            if error:
                quit_choice = "Quit"
                fixed_choice = "I fixed it, try again"
                override_choice = "Override the existing file"
                choice = ask_for_choice("Couldn't read the environment file, what do you want to do?", choices=[quit_choice, fixed_choice, override_choice])
                if choice == quit_choice:
                    raise UserQuit()
                elif choice == fixed_choice:
                    continue
                else:
                    break
            else:
                break

        if not keys:
            keys = EnvironmentFile(location, crypto, owner)

        if cache is not None:
            cache[location] = keys

        return keys

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

    def remove(self, key):
        """Remove a key"""
        Empty = type("Empty", (object, ), {})
        if self.keys.get(key, Empty) is not Empty:
            self._changed = True
            del self.keys[key]

    @property
    def encrypted_values(self):
        """Return our keys as a dictionary with encrypted values"""
        result = []
        log.info("Making encrypted values for environment variables")
        fingerprints = self.crypto.fingerprinted(self.keys)
        result = {"fingerprints": fingerprints}
        return result, self.keys.keys()

    def make_keys(self, contents):
        """Get us our keys from the contents of the file"""
        if contents.typ != self.type:
            raise BadKeyFile("Unknown type", type=contents.typ)
        keys = self.crypto.decrypt_by_fingerprint(contents.keys.get("fingerprints", {}), lambda *args, **kwargs: True)
        if not keys:
            return {}
        else:
            return keys

    def exports(self):
        """Return list of (key, val) exports we want to have in the shell"""
        return sorted(self.keys.items())

    def extra_env(self):
        """Return extra env stuff"""
        return getattr(self.owner, "extra_env", lambda: [])()

    @property
    def parent_path_part(self):
        """Return our parent path part"""
        return getattr(self.owner, "parent_path_part", None)

    @property
    def default_keys_type(self):
        """Empty keys is a dict"""
        return dict

    @property
    def default_keys_type_name(self):
        """Assume type is environment"""
        return "environment"

    def as_string(self):
        """Return information about keys as a string"""
        return "Environment vars! {0}".format(", ".join(self))

