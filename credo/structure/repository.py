from credo.asker import ask_for_choice, ask_for_public_keys, ask_for_choice_or_new
from credo.errors import UserQuit, BadConfiguration, RepoError
from credo.versioning import determine_driver

import logging
import json
import os

log = logging.getLogger("credo.versioning")

def configure(repo_name, location, new_remote=None, version_with=None):
    """Configure a repository"""
    repository = Repository(repo_name, location)
    if repository.versioned:
        remote = "<none set>"
        if repository.remote:
            remote = repository.remote

        remove_choice = "Stop versioning this directory"
        change_choice = "Change the remote of this directory"
        carryon_choice = "Keep the remote as is"

        if version_with == "nothing":
            choice = remove_choice
        elif version_with is None:
            choice = ask_for_choice(
                [ "This repo is already versioned\tremote={0}\tlocation={1}".format(remote, repository.location)
                , "What do you want to do?"
                ]
                , [remove_choice, change_choice, carryon_choice]
                )
        else:
            choice = change_choice

        if choice == remove_choice:
            repository.deleteme()
        elif choice == change_choice:
            repository.change_remote(new_remote, remote_type=version_with)
    else:
        change_choice = "Add versioning to this repository"
        carryon_choice = "Keep the repository unversioned"

        if version_with == "nothing":
            log.info("Repository is already unversioned")
        elif version_with is None:
            choice = ask_for_choice(
                [ "This repo is not versioned yet ({0})".format(repository.location)
                , "What do you want to do?"
                ]
                , [carryon_choice, change_choice]
                )
        else:
            choice = change_choice

        if choice == change_choice:
            repository.change_remote(new_remote, remote_type=version_with)

class Repository(object):
    """Understands how to version a directory"""
    def __init__(self, name, location):
        self.name = name
        self.location = location

        self.driver = determine_driver(location)

    def synchronize(self):
        """Ask the driver to synchronize the folder"""
        self.driver.synchronize()

    @property
    def versioned(self):
        """Say whether the driver is versioned or not"""
        return self.driver.versioned

    @property
    def remote(self):
        """Give back the remote the driver has"""
        return self.driver.remote

    def deleteme(self):
        """Tell the driver to delete himself"""
        self.driver.deleteme()

    def change_remote(self, new_remote=None, remote_type=None):
        """
        Determine what we want to change the remote to

        If passed in new_remote is None, we ask for a remote
        Only support git, so complain if remote_type is not "git", and set it to git if it is None
        """
        message = "What do you want as the new remote?"
        if self.driver.versioned:
            message = "{0} (currently {1}".format(message, self.remote)

            no_remote_choice = "Keep versioned, but remove our registered remote"
        else:
            no_remote_choice = "Setup versioning, but don't add a remote"

        quit_choice = "Quit"

        if new_remote is False:
            choice = no_remote_choice
        elif new_remote is not None:
            choice = new_remote
        else:
            choice = ask_for_choice_or_new(message, [quit_choice, no_remote_choice])

        if choice == quit_choice:
            raise UserQuit()
        elif choice == no_remote_choice:
            choice = None

        if remote_type is None:
            remote_type = "git"
        elif remote_type != "git":
            raise RepoError("Unsupported versioning type", type=remote_type)

        if not self.driver.versioned:
            self.driver = determine_driver(self.location, version_type=remote_type)
            self.driver.initialise(choice)
        else:
            self.driver.change_remote(choice)

    def add_change(self, message, changed_files, **info):
        """Ask the driver to add the changed files and commit with the provided message"""
        message_suffix = ", ".join("{0}={1}".format(key, val) for key, val in info.items())
        if message_suffix:
            message = "{0} ({1})".format(message, message_suffix)
        self.driver.add_change(message, changed_files)

    def get_public_keys(self, ask_anyway=False):
        """
        Return public keys for this repository as (urls, pems, locations)
        Where locations is a map of {<pem>: <location>} for when we know the location
        """
        keys_location = os.path.join(self.location, "keys")

        result = {}
        locations = {}

        if os.path.exists(keys_location):
            try:
                with open(keys_location) as fle:
                    result = json.load(fle)
            except ValueError as err:
                result = self.fix_keys(keys_location, err)

        if not os.path.exists(keys_location) or ask_anyway:
            urls, pems, locations = ask_for_public_keys(self.driver.remote)

            if "urls" not in result:
                result["urls"] = []
            if "pems" not in result:
                result["pems"] = []
            result["urls"].extend(urls)
            result["pems"].extend(pems)

        urls = result.get("urls")
        pems = result.get("pems")
        if urls or pems:
            try:
                content = json.dumps(result, indent=4)
            except ValueError as err:
                raise BadConfiguration("Couldn't write out keys json", err=err)

            log.debug("Writing out public keys\tlocation=%s", keys_location)
            with open(keys_location, 'w') as fle:
                fle.write(content)
            self.add_change("Adjusting known public keys", [keys_location], repo=self.name)

        return result.get("urls", []), result.get("pems", []), locations

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

