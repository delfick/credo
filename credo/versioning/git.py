from credo.errors import UserQuit, GitError, CredoProgrammerError
from credo.asker import ask_for_choice
from credo.versioning.base import Base

from contextlib import contextmanager
import tempfile
import logging
import shutil
import os

try:
    # Optional dependency is optional
    import pygit2
except ImportError:
    pygit2 = None

log = logging.getLogger("credo.versioning.git")

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

    def synchronize(self, override=False):
        """Pull in changes from our remote"""
        if not self.remote:
            return

        self.resolve_dirty_repo()
        if self.repo.status():
            raise CredoProgrammerError("Somehow there are still changes in the repo....")

        origin = self.origin
        res = origin.fetch()
        if any(res.values()):
            log.info("Pulled in changes from %s", origin.url)
            oid = self.repo.lookup_reference("refs/remotes/origin/master").target

            log.info("Resetting %s to origin/master (%s)", self.location, oid)
            self.repo.reset(oid, pygit2.GIT_RESET_HARD)
        else:
            try:
                origin.push("refs/heads/master")
            except ValueError as error:
                log.error("Failed to push to remote repository\tremote=%s\terror=%s", origin.url, error)

    def resolve_dirty_repo(self):
        """Wait for the user to resolve any changes already in the repo"""
        while True:
            if not self.repo.status():
                break

            quit_choice = "Quit"
            fixed_choice = "I fixed it, please continue"
            choice = ask_for_choice("Seems there is already changes\tlocation={0}".format(self.location), choices=[quit_choice, fixed_choice])
            if choice == quit_choice:
                raise UserQuit()
            elif self.repo.status():
                log.error("Ummm, there's still changes already in the repository...\tlocation=%s", self.location)

    def determine_remote(self):
        """Get us back the url of the origin remote"""
        if self.origin:
            return self.origin.url

    @property
    def origin(self):
        for remote in self.repo.remotes:
            if remote.name == "origin":
                return remote

    def set_origin(self, new_remote):
        """Set our origin remote to be the new remote"""
        for remote in self.repo.remotes:
            if remote.name == "origin":
                remote.url = new_remote
                return

        self.repo.create_remote("origin", new_remote)

    def get_git_user(self):
        """Get us a user for our git"""
        name = self.repo.config.get_multivar("user.name")
        if name:
            name = name[0]
        else:
            name = "Credo"

        email = self.repo.config.get_multivar("user.email")
        if email:
            email = email[0]
        else:
            email = "credo@nowhereinparticular.com"

        return pygit2.Signature(name, email)

    def current_commit(self):
        """Return the current commit"""
        head = self.repo.lookup_reference("HEAD")
        try:
            return [head.resolve().target]
        except KeyError:
            return []

    def add_change(self, message, changed_files):
        """Add a change to the repo"""
        if not changed_files:
            log.warning("Told to add a change, but no files were specified\tmessage=%s", message)
        elif changed_files is True:
            self.repo.index.add_all([])
        else:
            for filename in changed_files:
                self.repo.index.add(filename)

        self.repo.index.write()
        if any(status in (pygit2.GIT_STATUS_INDEX_DELETED, pygit2.GIT_STATUS_INDEX_MODIFIED, pygit2.GIT_STATUS_INDEX_NEW) for status in self.repo.status().values()):
            oid = self.repo.index.write_tree()
            author = committer = self.get_git_user()
            self.repo.create_commit('HEAD', author, committer, message, oid, self.current_commit())

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
        self.add_change("Initial commit", changed_files=True)
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
            log.info("Adding remote\tlocation=%s\tnew origin=%s", self.location, new_remote)

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

