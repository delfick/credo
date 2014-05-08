import os

def do_display(credulous, **kwargs):
    """Just print out the chosen creds"""
    access_key, secret_key = credulous.current_creds
    print "export AWS_ACCESS_KEY_ID='{0}'".format(access_key)
    print "export AWS_SECRET_ACCESS_KEY='{0}'".format(secret_key)

def do_exec(credulous, command, **kwargs):
    """Exec some command with aws credentials in the environment"""
    access_key, secret_key = credulous.current_creds
    environment = dict(os.environ)
    environment.update(AWS_ACCESS_KEY_ID=access_key, AWS_SECRET_ACCESS_KEY=secret_key)
    os.execvpe(command[0], command, environment)

