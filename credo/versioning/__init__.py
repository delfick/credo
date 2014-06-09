import os

def determine_driver(location):
    """Determine what versioning driver to use for some location"""
    if os.path.exists(os.path.join(location, ".git")):
        from credo.versioning.git import GitDriver
        return GitDriver(location)
    else:
        from credo.versioning.base import NoVersioningDriver
        return NoVersioningDriver(location)

