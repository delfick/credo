from credo.cred_types.saml import SamlInfo, SamlRole
from credo.cred_types.amazon import AmazonKeys
from credo.errors import BadCredentialFile
from credo.structure.keys import Keys
from credo.asker import get_response
from credo.amazon import IamSaml
import logging

log = logging.getLogger("credo.structure.credentials")

class Credentials(Keys):
    """Knows about credential files"""
    requires_encryption = True

    def save(self, force=False, half_life=None):
        """Save our credentials to file"""
        if self.keys.needs_rotation():
            self.keys.rotate(half_life)

        if force or self.changed or self.keys.changed:
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
        return "repo={0}|account={1}|user={2}|{3}".format(self.repo_name, self.account_name, self.name, self.path_name)

    @property
    def path_name(self):
        """Return this part of the path"""
        return "Credentials"

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

class SamlCredentials(Credentials):
    """Knows about saml information"""

    requires_encryption = False

    @property
    def path(self):
        return "role={0}|provider={1}|username={2}".format(self.role, self.provider, self.idp_username)

    @property
    def default_keys_type(self):
        """Empty keys is a list"""
        return dict

    @property
    def default_keys_type_name(self):
        """Assume type is amazon"""
        return "saml"

    @property
    def path_name(self):
        """Return this part of the path"""
        return "Saml Credentials"

    def as_string(self):
        """Return information about keys as a string"""
        return "Saml things!"

    def exports(self):
        """Export some values"""
        password = get_response("Password for idp user {0}".format(self.keys.idp_username), password=True)
        pair = IamSaml(self.keys.provider, self.keys.idp_username, password)
        return pair.exports(self.keys.role)

    @property
    def role(self):
        return self.keys.role

    @property
    def provider(self):
        return self.keys.provider

    @property
    def idp_username(self):
        return self.keys.idp_username

    def make_keys(self, contents):
        """Get us some keys"""
        if contents.typ != "saml":
            raise BadCredentialFile("Unknown credentials type", found=contents.typ, location=contents.location)

        if not contents.keys:
            contents.keys["role"] = self.role.encrypted_values()
            contents.keys["provider"] = self.provider
            contents.keys["idp_username"] = self.idp_username
        return SamlInfo(contents.keys["provider"], SamlRole(*contents.keys["role"].split(",")), contents.keys["idp_username"])

