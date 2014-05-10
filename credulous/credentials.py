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

