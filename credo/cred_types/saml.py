import re

class SamlRole(object):
    def __init__(self, principal_arn, role_arn):
        self.role_arn = role_arn
        self.principal_arn = principal_arn
        info = re.match("arn:aws:iam::(?P<account_id>[^:]+):role/(?P<role_name>.+)", self.role_arn).groups()
        self.account_id, self.role_name = info

    def __str__(self):
        return "{0} : {1}".format(self.account_id, self.role_name)

    def encrypted_values(self):
        return "{0},{1}".format(self.principal_arn, self.role_arn)

class SamlInfo(object):
    type = "saml"

    def __init__(self, provider, role, idp_username):
        self.role = role
        self.provider = provider
        self.idp_username = idp_username
        self.changed = True

    def needs_rotation(self):
        return False

    @property
    def access_keys(self):
        return []

    def unchanged(self):
        self.changed = False

    @property
    def encrypted_values(self):
        return {"provider": self.provider, "role": self.role.encrypted_values(), "idp_username": self.idp_username}, []

