from credo.errors import CredoError
import logging
import os

log = logging.getLogger("credo.versioning")

try:
    import pygit2
except ImportError:
    pygit2 = None

def has_git_abilities():
    """Useful if anything wants to know if we can git"""
    return pygit2 is not None

def determine_driver(location, version_type=None):
    """Determine what versioning driver to use for some location"""
    if version_type == "git" or os.path.exists(os.path.join(location, ".git")):
        if pygit2 is not None:
            from credo.versioning.git import GitDriver
            return GitDriver(location)
        else:
            log.warning("Can't import pygit2, so not doing any git things")
            version_type = None

    if version_type is None:
        from credo.versioning.base import NoVersioningDriver
        return NoVersioningDriver(location)

    raise CredoError("Unknown versioning type", version_type=version_type)

