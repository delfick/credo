from credo.structure.encrypted_keys import EncryptedKeys
from credo.cred_types.amazon import AmazonKeys
from credo.errors import BadCredentialFile

import logging

log = logging.getLogger("credo.structure.credentials")

class Credentials(EncryptedKeys):
    """Knows about credential files"""

    def save(self, force=False):
        """Save our credentials to file"""
        if self.keys.needs_rotation():
            self.keys.rotate()

        if force or self.keys.changed:
            self.contents.save(self.location, self.keys, access_keys=list(self.keys.access_keys))
            self.keys.unchanged()

            cred_path = self.credential_path
            self.credential_path.add_change("Saving new keys", [self.location]
                , repo=cred_path.repository.name, account=cred_path.account.name, user=cred_path.user.name
                )

    def invalidate_creds(self):
        """Mark our creds as invalid"""
        cred_path = self.credential_path
        log.info("Marking the credentials as invalid\trepo=%s\taccount=%s\tuser=%s", cred_path.repository.name, cred_path.account.name, cred_path.user.name)
        self.keys.invalidate_all()

    @property
    def path(self):
        """Return the repo, account and user this represents"""
        return "repo={0}|account={1}|user={2}|Credentials".format(self.repo_name, self.account_name, self.name)

    @property
    def parent_path_part(self):
        """Return our user"""
        return self.credential_path.user

    def make_keys(self, contents):
        """Get us some keys"""
        if contents.typ != "amazon":
            raise BadCredentialFile("Unknown credentials type", found=contents.typ, location=contents.location)
        return AmazonKeys(contents.keys, self.credential_path)

    def exports(self):
        """The exports specific to the credentials stored"""
        return self.keys.exports()

    @property
    def default_keys_type(self):
        """Empty keys is a list"""
        return list

    @property
    def default_keys_type_name(self):
        """Assume type is amazon"""
        return "amazon"

    def as_string(self):
        """Return information about keys as a string"""
        return "keys!"
