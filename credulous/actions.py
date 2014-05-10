import os

def do_display(credulous, **kwargs):
    """Just print out the chosen creds"""
    access_key, secret_key = credulous.current_creds
    exportable = lambda key, val: "export {0}='{1}'".format(key, val)
    maybe = lambda key: getattr(credulous, key, None)

    print exportable("AWS_ACCESS_KEY_ID", access_key)
    print exportable("AWS_SECRET_ACCESS_KEY", secret_key)
    print exportable("CREDULOUS_CURRENT_REPO", maybe("repo"))
    print exportable("CREDULOUS_CURRENT_ACCOUNT", maybe("account"))
    print exportable("CREDULOUS_CURRENT_USER", maybe("user"))

def do_exec(credulous, command, **kwargs):
    """Exec some command with aws credentials in the environment"""
    access_key, secret_key = credulous.current_creds
    environment = dict(os.environ)
    environment.update(AWS_ACCESS_KEY_ID=access_key, AWS_SECRET_ACCESS_KEY=secret_key)
    os.execvpe(command[0], command, environment)

