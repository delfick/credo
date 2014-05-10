class Credentials(object):
    """Knows about credential files"""
    def __init__(self, location, repo, account, user):
        self.user = user
        self.repo = repo
        self.account = account
        self.location = location

    @property
    def access_key(self):
        return "1"

    @property
    def secret_key(self):
        return "2"

    def as_string(self):
        """Return information about credentials as a string"""
        return "Credentials!"

    def shell_exports(self):
        """Return list of (key, val) exports we want to have in the shell"""
        return [
              ("AWS_ACCESS_KEY_ID", self.access_key)
            , ("AWS_SECRET_ACCESS_KEY", self.secret_key)
            , ("CREDULOUS_CURRENT_REPO", self.repo)
            , ("CREDULOUS_CURRENT_ACCOUNT", self.account)
            , ("CREDULOUS_CURRENT_USER", self.user)
            ]

