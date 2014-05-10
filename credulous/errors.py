class CredulousError(Exception):
    """Helpful class for creating custom exceptions"""
    desc = ""

    def __init__(self, message="", **kwargs):
        self.kwargs = kwargs
        self.message = message
        super(CredulousError, self).__init__(message)

    def __str__(self):
        desc = self.desc
        message = self.message

        info = ["{0}={1}".format(k, v) for k, v in sorted(self.kwargs.items())]
        info = '\t'.join(info)
        if info and (message or desc):
            info = "\t{0}".format(info)

        if desc:
            if message:
                message = ". {0}".format(message)
            return '"{0}{1}"{2}'.format(desc, message, info)
        else:
            if message:
                return '"{0}"{1}'.format(message, info)
            else:
                return "{0}".format(info)

class NoExecCommand(CredulousError):
    desc = "No exec command to execute"

class NoConfigFile(CredulousError):
    desc = "No config file"

class BadConfigFile(CredulousError):
    desc = "Bad config file"

class NotEnoughInfo(CredulousError):
    desc = "Need more information"

class BadConfig(CredulousError):
    desc = "Bad Config"

class BadCredentialFile(CredulousError):
    desc = "Bad credentials file"

class BadPrivateKey(CredulousError):
    desc = "Bad private ssh key"

class BadCypherText(CredulousError):
    desc = "Couldn't decrypt text"

