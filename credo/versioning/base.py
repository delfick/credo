class Base(object):
    """Everything a versioning driver needs to know"""
    def __init__(self, location):
        self.location = location

    def synchronize(self):
        """Make sure we are in sync with our external location"""
        raise NotImplementedError()

    @property
    def remote(self):
        """Return the address of our external location"""
        return self.determine_remote()

    def determine_remote(self):
        """Figure out what our remote is"""
        raise NotImplementedError()

    def add_change(self, message, change_files):
        """Add a change locally that gives specified message or changes in the specified files"""
        raise NotImplementedError()

class NoVersioningDriver(Base):
    """Basically no-ops everything"""
    def synchronize(self): pass
    def determine_remote(self): return None
    def add_change(self, message, change_files): pass

