from credo.errors import UserQuit, GitError
from credo.asker import ask_for_choice
from credo.versioning.base import Base

from contextlib import contextmanager
import tempfile
import logging
import shutil
import pygit2
import os

log = logging.getLogger(name="credo.versioning.git")

class GitDriver(Base):
    """Knows how to git"""
    def __init__(self, location):
        self.location = location

    @property
    def repo(self):
        """Get a repository object"""
        if not hasattr(self, "_repo"):
            self._repo = pygit2.Repository(self.location)
        return self._repo

    def synchronize(self):
        """Stash any changes, fetch, reset, push, unstash"""

    def determine_remote(self):
        """Get us back the url of the origin remote"""
        for remote in self.repo.remotes:
            if remote.name == "origin":
                return remote.url

    def set_origin(self, new_remote):
        """Set our origin remote to be the new remote"""
        for remote in self.repo.remotes:
            if remote.name == "origin":
                remote.url = new_remote
                return

        self.repo.create_remote("origin", new_remote)

    def add_change(self, message, changed_files):
        pass

    def is_versioned(self):
        """Yes we are versioned"""
        return True

    def deleteme(self):
        """Delete the versioning!"""
        quit_choice = "Quit"
        confirm_choice = "Yes I do want to delete!"

        git_folder = os.path.join(self.location, ".git")
        choice = ask_for_choice("Are you sure you want to remove {0}?".format(git_folder), [quit_choice, confirm_choice])
        if choice == quit_choice:
            raise UserQuit()
        else:
            shutil.rmtree(git_folder)

    def initialise(self, new_remote=None):
        """Setup the .git folder, with optional remote"""
        log.info("Setting up a .git folder")
        git_folder = os.path.join(self.location, ".git")
        if os.path.exists(git_folder):
            raise GitError("Trying to initialise git, but .git folder already exists", location=self.location)

        pygit2.init_repository(self.location)
        if new_remote:
            self.change_remote(new_remote)

    def change_remote(self, new_remote):
        """Setup our new remote!"""
        if new_remote is None and self.remote:
            log.info("Removing current remote (%s)", self.remote)
        elif self.remote:
            if self.remote != new_remote:
                log.info("Changing remote to %s from %s", new_remote, self.remote)
            else:
                log.info("Remote for this repository is already %s", new_remote)
        elif new_remote:
            log.info("Adding remote to %s", new_remote)

        if new_remote is None:
            if self.remote:
                self.repo.remote_remote("origin")
        elif new_remote != self.remote:
            with self.temp_clone(new_remote):
                self.set_origin(new_remote)
                self.remote = new_remote

    @contextmanager
    def temp_clone(self, url):
        """Clone a url into a temporary place, yield that place, then delete it"""
        tmpdir = None
        try:
            tmpdir = tempfile.mkdtemp()
            repo = os.path.join(tmpdir, "repo")
            try:
                pygit2.clone_repository(url, repo)
            except pygit2.GitError as error:
                raise GitError("Couldn't clone the new remote", url=url, repo=self.location, error_type=error.__class__.__name__, error=error)
            yield repo
        finally:
            if os.path.exists(tmpdir):
                shutil.rmtree(tmpdir)

