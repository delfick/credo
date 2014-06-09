from pygit2 import Repository as GitRepository

class GitDriver(object):
    """Knows how to git"""
    def __init__(self, location):
        self.location = location
        self.repo = GitRepository(self.location)

    def synchronize(self):
        """Stash any changes, fetch, reset, push, unstash"""

    @property
    def remote(self):
        """Get us back the url of the origin remote"""

    def add_change(self, message, changed_files):
        pass

