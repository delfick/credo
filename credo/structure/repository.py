from credo.asker import ask_for_choice, ask_for_choice_or_new
from credo.cred_types.environment import EnvironmentMixin
from credo.versioning import has_git_abilities
from credo.errors import UserQuit, RepoError
from credo.versioning import determine_driver
from credo.pub_keys import PubKeySyncer

import logging
import os

log = logging.getLogger("credo.structure.repository")

def synchronize(repo_name, location, crypto):
    """Synchronise this repository"""
    repository = Repository(repo_name, location, crypto)
    if repository.versioned:
        repository.synchronize()

def configure(repo_name, location, crypto, new_remote=None, version_with=None):
    """Configure a repository"""
    repository = Repository(repo_name, location, crypto)
    if repository.versioned:
        remote = "<none set>"
        if repository.remote:
            remote = repository.remote

        remove_choice = "Stop versioning this directory"
        change_choice = "Change the remote of this directory"
        carryon_choice = "Keep the remote as is"

        if version_with == "nothing":
            choice = remove_choice
        elif new_remote is None and version_with is None:
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

class Repository(object, EnvironmentMixin):
    """Understands how to version a directory"""
    def __init__(self, name, location, crypto):
        self.name = name
        self.crypto = crypto
        self.location = location

        self.driver = determine_driver(location)

        root_dir = os.path.join(os.path.dirname(self.location), "..")
        self.pub_key_syncer = PubKeySyncer(root_dir, self)

    def synchronize(self, override=False):
        """Ask the driver to synchronize the folder"""
        self.driver.synchronize(override=override)

    @property
    def path(self):
        """Return the repo this represents"""
        return "repo={0}".format(self.name)

    @property
    def path_parts(self):
        """Return the objects in the path to here"""
        return ()

    def extra_env(self):
        """Define default env stuff"""
        return [("CREDO_CURRENT_REPO", self.name)]

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
            if not has_git_abilities():
                raise RepoError("Sorry, no pygit2, can't do git things")
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

        changes = []
        for filename in changed_files:
            if filename.startswith("/"):
                changes.append(os.path.relpath(filename, start=self.location))
            else:
                changes.append(filename)

        self.driver.add_change(message, changes)

