from credo.errors import CredoError
import os

def determine_driver(location, version_type=None):
    """Determine what versioning driver to use for some location"""
    if version_type == "git" or os.path.exists(os.path.join(location, ".git")):
        from credo.versioning.git import GitDriver
        return GitDriver(location)
    elif version_type is None:
        from credo.versioning.base import NoVersioningDriver
        return NoVersioningDriver(location)
    else:
        raise CredoError("Unknown versioning type", version_type=version_type)

