from credo.structure.encrypted_keys import EncryptedKeys
from credo.cred_types.amazon import AmazonKeys
from credo.errors import BadCredentialFile

import logging

log = logging.getLogger("credo.structure")

class Credentials(EncryptedKeys):
    """Knows about credential files"""

    def save(self, force=False):
        """Save our credentials to file"""
        if self.keys.needs_rotation():
            self.keys.rotate()

        if force or self.keys.changed:
            self.contents.save(self.location, self.keys, access_keys=self.keys.access_keys)
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

    def make_keys(self, contents):
        """Get us some keys"""
        if contents.typ != "amazon":
            raise BadCredentialFile("Unknown credentials type", found=contents.typ, location=contents.location)
        return AmazonKeys(contents.keys, self.credential_path)

    def shell_exports(self):
        """Return list of (key, val) exports we want to have in the shell"""
        cred_path = self.credential_path
        return self.keys.exports() + cred_path.repository.shell_exports() + cred_path.account.shell_exports() + cred_path.user.shell_exports() + [
              ("CREDO_CURRENT_REPO", cred_path.repository.name)
            , ("CREDO_CURRENT_USER", cred_path.user.name)
            , ("CREDO_CURRENT_ACCOUNT", cred_path.account.name)
            ]

    def default_keys_type(self):
        """Empty keys is a list"""
        return list

    def default_keys_type_name(self):
        """Assume type is amazon"""
        return "amazon"

    def as_string(self):
        """Return information about keys as a string"""
        return "keys!"
