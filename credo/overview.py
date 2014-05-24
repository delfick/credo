from credo.errors import NoConfigFile, BadConfigFile, CredoError, BadConfiguration
from credo.asker import ask_for_choice, ask_for_choice_or_new
from credo.loader import CredentialInfo, Loader
from credo.explorer import Explorer

import requests
import logging
import json
import time
import os

log = logging.getLogger("credo.overview")

class Unspecified(object):
    """Telling the difference between None and just not specified"""

class Credo(object):
    """Incredible credo knows all"""

    def __init__(self, crypto):
        self.crypto = crypto

    @property
    def chosen(self):
        """Return our chosen creds"""
        if not hasattr(self, "_chosen"):
            self._chosen = self.find_credentials()
            self.add_public_keys(self._chosen.credential_info.repository, self.crypto)
            self.set_options(repo=self._chosen.credential_info.repo, account=self._chosen.credential_info.account, user=self._chosen.credential_info.user)
        return self._chosen

    def make_explorer(self):
        """Make us an explorer"""
        return Explorer(self.root_dir, self.crypto)

    def find_credentials(self, completed=None, chain=None, chosen=None):
        """
        Traverse our directory structure, asking as necessary

        and return the credentials object we find
        """
        if completed is None:
            completed, _ = self.make_explorer().filtered(repo=self.repo, account=self.account, user=self.user)

        if chain is None:
            chain = [("repo", "Repository"), ("account", "Account"), ("user", "User")]

        if chosen is None:
            chosen = []

        nxt, category = chain.pop(0)
        if len(completed) is 1:
            val = completed.keys()[0]
        else:
            if not completed:
                raise CredoError("Told to find a key that doesn't exist", repo=self.repo, account=self.account, user=self.user)
            val = ask_for_choice(category, sorted(completed.keys()))

        chosen.append((nxt, val))
        if not chain:
            return completed[val]
        else:
            return self.find_credentials(completed[val], list(chain), list(chosen))

    def make_credentials(self, directory_structure=None, chain=None, chosen=None):
        """
        Traverse our directory structure, asking as necessary

        and create new parts of the structure as necessary
        """
        if directory_structure is None:
            directory_structure = self.make_explorer().directory_structure

        if chain is None:
            chain = [("repos", "repo", "Repository"), ("accounts", "account", "Account"), ("users", "user", "User")]

        if chosen is None:
            chosen = []

        container, nxt, category = chain.pop(0)
        if container not in directory_structure:
            directory_structure[container] = {}

        if getattr(self, nxt, None):
            val = getattr(self, nxt)
        else:
            val = ask_for_choice_or_new(category, sorted(key for key in directory_structure[container].keys() if not key.startswith('/')))

        location = os.path.join(directory_structure['/location/'], val)
        if val not in directory_structure[container]:
            directory_structure[container][val] = {'/files/': [], '/location/': location}

        chosen.append((nxt, val))
        if not chain:
            credentials = None
            if container in directory_structure and val in directory_structure[container]:
                credentials = directory_structure[container][val].get('/credentials/')

            credentials_location = os.path.join(location, "credentials.json")
            if not credentials or os.path.abspath(credentials_location) != os.path.abspath(credentials.location):
                chosen.append(("location", credentials_location))
                credential_info = CredentialInfo(**dict(chosen))

                credentials = Loader.from_file(credential_info, self.crypto, default_type="amazon")
                if credential_info.location not in directory_structure['/files/']:
                    directory_structure['/files/'].append(credential_info.location)
                directory_structure['/credentials/'] = credentials
            return credentials
        else:
            return self.make_credentials(directory_structure[container][val], list(chain), list(chosen))

    def find_options(self, config_file=Unspecified, root_dir=Unspecified, **kwargs):
        """Setup the credo!"""
        if config_file is Unspecified:
            config_file = self.find_config_file(config_file)

        if config_file:
            if not os.path.exists(config_file):
                raise NoConfigFile("Specified location is empty", location=config_file)
            if not os.access(config_file, os.R_OK):
                raise BadConfigFile("Config file isn't readable", location=config_file)

            self.read_from_config(config_file)

        # Override the root dir if supplied
        if root_dir is not Unspecified:
            self.root_dir = root_dir

        self.set_options(**kwargs)

    def set_options(self, **kwargs):
        """Set specific options"""
        if not getattr(self, "user", None) and not getattr(self, "account", None) and kwargs.get("creds"):
            creds = kwargs["creds"]
            if '@' not in creds:
                raise BadConfiguration("Creds option needs to be user@account", got=creds)

            user, account = creds.split("@")
            self.user = user.strip()
            self.account = account.strip()

        for attribute in ("user", "account", "repo"):
            if not getattr(self, attribute, None) and attribute in kwargs:
                setattr(self, attribute, kwargs[attribute])

    def find_config_file(self, config_file=Unspecified):
        """Find a config file, use the one given if specified"""
        if config_file is not Unspecified:
            return config_file

        credo_home = os.path.expanduser("~/.credo")
        home_config = os.path.join(credo_home, "config.json")
        if os.path.exists(home_config) and os.stat(home_config).st_size > 0:
            return home_config

        if not os.path.exists(credo_home):
            os.makedirs(credo_home)
        json.dump({"root_dir": os.path.expanduser("~/.credo/repos")}, open(home_config, "w"))
        return home_config

    def read_from_config(self, config_file):
        """Call find_options using options from the config file"""
        # What's an error handling?
        options = json.load(open(config_file))
        options["config_file"] = None
        self.find_options(**options)

    def add_public_keys(self, repository, crypto):
        """Find public keys for this repo and add them to the crypto object"""
        info = {}
        while not crypto.can_encrypt:
            if info == {}:
                urls, pems, locations = repository.get_public_keys()
                info["urls"] = urls
                info["pems"] = pems
                info["locations"] = locations

            downloaded = []
            for url in info["urls"]:
                downloaded.extend(self.download_pems(url))
            info["pems"].extend(downloaded)

            for pem in info["pems"]:
                location = info["locations"].get(pem)
                fingerprint = crypto.add_public_keys([pem]).get(pem)
                if not fingerprint:
                    log.error("Failed to add public key\tpem=%s", pem)
                else:
                    if location:
                        log.debug("Adding a public key\tlocation=%s\tfingerprint=%s", location, fingerprint)
                    else:
                        log.debug("Adding a public key\tfingerprint=%s", fingerprint)

            if not crypto.can_encrypt:
                log.error("Was unable to find any public keys")
                del info["urls"]
                del info["pems"]

    def download_pems(self, url):
        """Get pems from some url"""
        cache = {}
        cache_location = os.path.join(self.root_dir, "cache")
        if os.path.exists(cache_location):
            try:
                with open(cache_location) as fle:
                    cache = json.load(fle)
            except ValueError as err:
                log.warning("Failed to load the pem url cache\tlocation=%s\terr=%s", cache_location, err)
        else:
            log.debug("No cache to load urls from\tlocation=%s", cache_location)

        last_downloaded = None
        if url in cache.get("cached", {}):
            if "times" in cache and url in cache["times"]:
                last_downloaded = cache["times"][url]
                if not isinstance(last_downloaded, float) and not isinstance(last_downloaded, int):
                    last_downloaded = None

                else:
                    diff = time.time() - last_downloaded
                    if diff < 0 or diff > 3600:
                        log.info("Cache for %s is older than an hour, re-getting the keys", url)
                        last_downloaded = None

        cached = []
        if last_downloaded is not None and url in cache.get("cached", {}):
            cached = cache["cached"][url]
            if isinstance(cached, list) and all(isinstance(pem, basestring) for pem in cached):
                log.info("Using %s cached pem keys from %s", len(cached), url)
                return cached

        if "times" not in cache:
            cache["times"] = {}
        cache["times"][url] = time.time()

        if "cached" not in cache:
            cache["cached"] = {}

        try:
            lines = requests.get(url).content.split('\n')
        except requests.exceptions.RequestException as err:
            lines = None
            log.error("Failed to get pem keys from url\turl=%s\terr=%s\treason=%s", url, err.__class__.__name__, err)
            if cached:
                log.info("Using %s keys from cache of %s", len(cached), url)

        if lines:
            cached = []
            for line in lines:
                if line.startswith("ssh-rsa"):
                    cached.append(line)

            cache["cached"][url] = cached
            log.info("Got %s keys from %s", len(cached), url)

            try:
                with open(cache_location, "w") as fle:
                    json.dump(cache, fle)
            except ValueError as err:
                log.error("Couldn't write cache\tlocation=%s\terr=e%s", cache_location, err)

        return cached

