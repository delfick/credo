class Base(object):
    """Everything a versioning driver needs to know"""
    def __init__(self, location):
        self.location = location

    @property
    def remote(self):
        """Return the address of our external location"""
        if not hasattr(self, "_remote"):
            self._remote = self.determine_remote()
        return self._remote

    @remote.setter
    def remote(self, val):
        """Record a new remote"""
        self._remote = val

    @property
    def versioned(self):
        """Say whether we are versioned"""
        return self.is_versioned()

    def is_versioned(self):
        """Boolean saying whether we are versioned"""
        raise NotImplementedError()

    def determine_remote(self):
        """Figure out what our remote is"""
        raise NotImplementedError()

    def add_change(self, message, change_files):
        """Add a change locally that gives specified message or changes in the specified files"""
        raise NotImplementedError()

    def synchronize(self, override=False):
        """Make sure we are in sync with our external location"""
        raise NotImplementedError()

    def deleteme(self):
        """Delete what is necessary to stop versioning"""
        raise NotImplementedError()

    def initialise(self, new_remote=None):
        """Initialise the versioning!"""
        raise NotImplementedError()

    def change_remote(self, new_remote):
        """Setup the new remote"""
        raise NotImplementedError()

class NoVersioningDriver(Base):
    """Basically no-ops everything"""
    def deleteme(self): pass
    def initialise(self, new_remote=None): pass
    def add_change(self, message, change_files): pass
    def synchronize(self, override=False): pass
    def is_versioned(self): return False
    def change_remote(self): pass
    def determine_remote(self): return None

