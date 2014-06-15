from credo.asker import ask_for_choice, ask_for_public_keys
from credo.errors import BadConfiguration, UserQuit

import requests
import logging
import json
import time
import os

log = logging.getLogger("credo.overview")

class PubKeySyncer(object):
    """Knows about what public keys we can encrypt with"""
    def __init__(self, root_dir, repository):
        self.repository = repository
        self.crypto = self.repository.crypto
        self.root_dir = root_dir

    def sync(self, ask_anyway=False):
        """
        Find public keys for this repository and add them to the crypto object
        And remove public keys we don't know about anymore
        """
        info = {}
        added = []
        crypto = self.crypto

        while ask_anyway or not crypto.can_encrypt:
            if "urls" not in info:
                info["urls"] = []
            if "pems" not in info:
                info["pems"] = []
            if "locations" not in info:
                info["locations"] = {}

            urls, pems, locations, new_ones = self.get_public_keys(ask_anyway=ask_anyway, known_private_key_fingerprints=self.crypto.private_key_fingerprints)
            if not new_ones and ask_anyway:
                break

            info["urls"].extend(urls)
            info["pems"].extend(pems)
            info["locations"].update(locations)

            downloaded = []
            for url in info.get("urls", []):
                downloaded.extend(self.download_pems(url))
            info["pems"].extend(downloaded)

            for pem in info["pems"]:
                location = info["locations"].get(pem)
                fingerprint = crypto.add_public_keys([pem]).get(pem)
                added.append(fingerprint)
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
            else:
                break

        for fingerprint in crypto.public_key_fingerprints:
            if fingerprint not in added:
                log.info("Removing public key we aren't encrypting with anymore\tfingerprint=%s", fingerprint)
                crypto.remove_public_key()

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

    def get_public_keys(self, ask_anyway=False, known_private_key_fingerprints=None, remote=None):
        """
        Return public keys for this repository as (urls, pems, locations, new_ones)
        Where locations is a map of {<pem>: <location>} for when we know the location
        and new_ones says whether we got any new ones from the user
        """
        keys_location = os.path.join(self.repository.location, "keys")

        result = {}
        locations = {}

        if os.path.exists(keys_location):
            try:
                with open(keys_location) as fle:
                    result = json.load(fle)
            except ValueError as err:
                result = self.fix_keys(keys_location, err)

        new_ones = False
        if not os.path.exists(keys_location) or ask_anyway:
            urls, pems, locations = ask_for_public_keys(remote, known_private_key_fingerprints)
            if urls or pems:
                new_ones = True

            if "urls" not in result:
                result["urls"] = []
            if "pems" not in result:
                result["pems"] = []
            result["urls"].extend(urls)
            result["pems"].extend(pems)

        urls = result.get("urls", [])
        pems = result.get("pems", [])

        if urls or pems:
            try:
                content = json.dumps(result, indent=4)
            except ValueError as err:
                raise BadConfiguration("Couldn't write out keys json", err=err)

            log.debug("Writing out public keys\tlocation=%s", keys_location)
            dirname = os.path.dirname(keys_location)
            if not os.path.exists(dirname):
                os.makedirs(dirname)
            with open(keys_location, 'w') as fle:
                fle.write(content)
            self.repository.add_change("Adjusting known public keys", [keys_location], repo=self.repository.name)

        return urls, pems, locations, new_ones

    def fix_keys(self, location, error):
        """Get user to fix the keys file"""
        info = {"error": error}
        while True:
            quit_choice = "Quit"
            remove_choice = "Remove the file"
            try_again_choice = "I fixed it, Try again"
            choices = [try_again_choice, remove_choice, quit_choice]
            response = ask_for_choice("Couldn't load {0} as a json file ({1})".format(location, info["error"]), choices)

            if response == quit_choice:
                raise UserQuit()

            elif response == remove_choice:
                os.remove(location)
                return {}

            else:
                try:
                    return json.load(location)
                except ValueError as err:
                    info["error"] = err

