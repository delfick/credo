from credo.errors import CantEncrypt, CantSign
from credo.helper import print_list_of_tuples
from credo.asker import ask_user_for_secrets

import logging
import os

log = logging.getLogger("credo.actions")

def do_display(credo, **kwargs):
    """Just print out the chosen creds"""
    for key, val in credo.chosen.shell_exports():
        print "export {0}={1}".format(key, val)

def do_exec(credo, command, **kwargs):
    """Exec some command with aws credentials in the environment"""
    environment = dict(os.environ)
    environment.update(dict(credo.chosen.shell_exports()))
    os.execvpe(command[0], command, environment)

def do_import(credo, source=False, **kwargs):
    """Import some creds"""
    credentials = credo.make_credentials()
    credo.add_public_keys(credo.repo, credo.crypto)
    log.debug("Crypto has private keys %s", credo.crypto.private_key_fingerprints)
    log.debug("Crypto has public_keys %s", credo.crypto.public_key_fingerprints)

    if not credo.crypto.can_encrypt:
        raise CantEncrypt("No public keys to encrypt with", repo=credo.repo)
    if not credo.crypto.can_sign:
        raise CantSign("No private keys with matching public keys to sign with", repo=credo.repo)

    access_key, secret_key = ask_user_for_secrets(source=source)
    credentials.add_key(access_key, secret_key)
    credentials.save()
    print "Created credentials at {0}".format(credentials.location)

def do_rotate(credo, **kwargs):
    """Rotate some keys"""
    credentials = credo.chosen
    counts = credentials.rotate()
    print "Created {0} credentials and deleted {1} credentials".format(counts.get("created"), counts.get("deleted"))

def do_showavailable(credo, force_show_all=False, collapse_if_one=True, **kwargs):
    """Show all what available repos, accounts and users we have"""
    explorer = credo.make_explorer()

    if force_show_all:
        completed, fltr = explorer.completed, []
    else:
        completed, fltr = explorer.filtered(repo=credo.repo, account=credo.account, user=credo.user)

    print_list_of_tuples(fltr, "Using the filters")

    headings = ["Repositories", "Accounts", "Users"]

    def get_displayable(root, headings, indent="", underline_chain=None, sofar=None):
        """
        Return a structure for printing out our available credentials
        return as (heading, children)

        Where children is
            {child: (heading, grandchildren), child2: (heading, grandchildren)}
        """
        if sofar is None:
            sofar = []

        if underline_chain is None:
            underline_chain = ["="]

        def get_indented(s, prefix=""):
            """Print the string with leading indentation"""
            return "{0}{1}{2}".format(indent, prefix, s)

        def get_underlined(s, underline):
            """Get the indented str with an indented underline"""
            if underline:
                return "{0}\n{1}".format(get_indented(s), get_indented(underline * len(s)))
            else:
                return "{0}:".format(get_indented(s, ">> "))

        if not headings:
            return root
        else:
            heading = headings.pop(0)

            heading_underline = None
            if underline_chain:
                heading_underline = underline_chain.pop(0)

            children = {}
            for key, val in root.items():
                indented_key = get_indented(key)
                children[indented_key] = get_displayable(val, list(headings), indent + "    ", list(underline_chain), list(sofar) + [indented_key])

            if not children:
                return None
            return get_underlined(heading, heading_underline), children

    def display_creds(cred, indent=""):
        """Display info about the creds"""
        as_string = cred.as_string()
        for line in as_string.split('\n'):
            print "{0}{1}".format(indent * 3, line)

    def display_result(result):
        """Display the result from get_displayable"""
        heading, children = result
        print ""
        print heading
        for child, values in children.items():
            print ""
            print child
            if isinstance(values, list) or isinstance(values, tuple) or isinstance(values, dict):
                display_result(values)
            elif values:
                display_creds(values, "    ")

    # Complain if no found credentials
    if not completed:
        print "Didn't find any credential files"
        return

    # Special case if we only found one
    if collapse_if_one:
        r = completed
        chain = []
        while True:
            if not r:
                break

            if len(r) > 1:
                break

            chain.append(r.keys()[0])
            r = r[r.keys()[0]]
            if not isinstance(r, list) and not isinstance(r, tuple) and not isinstance(r, dict):
                print_list_of_tuples(zip(["repo", "account", "user"], chain), "Only found one set of credentials")
                display_creds(r)
                return

    # Or just do them all if found more than one
    result = get_displayable(completed, headings)
    display_result(result)

