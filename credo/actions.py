from credo.asker import ask_user_for_secrets, ask_user_for_half_life, ask_for_choice_or_new, ask_for_env
from credo.errors import CantEncrypt, CantSign, BadCredential, CredoError
from credo.helper import print_list_of_tuples, make_export_commands
from credo.amazon import IamPair
from credo import structure

import logging
import os

log = logging.getLogger("credo.actions")

def do_current(credo, **kwargs):
    """Print out what user is currently in our environment"""
    if "AWS_ACCESS_KEY_ID" not in os.environ or "AWS_SECRET_ACCESS_KEY" not in os.environ:
        print "There are currently no credentials in your environment!"
    else:
        iam_pair = IamPair.from_environment()
        print "Asking amazon for details"
        if not iam_pair.works:
            print "Your current credentials are not valid...."
        else:
            aliases = iam_pair.ask_amazon_for_account_aliases()
            if not aliases:
                aliases = ["<no_account_alias>"]
            print "You are currently \"{0}\" from \"{1}\" (account {2})".format(
                iam_pair.ask_amazon_for_username(), aliases[0], iam_pair.ask_amazon_for_account()
                )

def do_unset(credo, **kwargs):
    """Just print out the exports and unsets necessary to unset credo exports"""
    exports = []
    for key, val in os.environ.items():
        if key.startswith("CREDO_UNSET"):
            name = key[12:]
            exports.append((name, val))
            exports.append((key, "CREDO_UNSET"))

    for command in make_export_commands(exports):
        print(command)

def do_exports(credo, chosen=None, repository=None, **kwargs):
    """Just print out the chosen creds"""
    if chosen is None:
        chosen = credo.chosen

    if repository is None:
        repository = credo.chosen.credential_path.repository

    shell_exports = {}
    for key, val in chosen.shell_exports():
        shell_exports[key] = val

    if not shell_exports:
        print("# {0} has no environment variables".format(chosen.path))

    unsetters = {}
    for key, val in shell_exports.items():
        name = "CREDO_UNSET_{0}".format(key)
        if key not in os.environ or os.environ[key] == val:
            unsetters[name] = "CREDO_UNSET"
        else:
            unsetters[name] = os.environ[key]

    print("## Find values to unset")
    do_unset(credo)

    print("\n## Values to be set now")
    for command in make_export_commands(sorted(shell_exports.items())):
        print(command)

    print("\n## And unsetters for when we change")
    for command in make_export_commands(sorted(unsetters.items()), no_transform=True):
        print(command)

    repository.synchronize()

def do_capture(credo, env=None, remove_env=None, all_accounts=False, all_users=False, find_user=False, **kwargs):
    """Capture environment variables"""
    part = credo.find_credential_path_part(all_accounts=all_accounts, all_users=all_users, find_user=find_user)
    if hasattr(part, "credential_path"):
        repository = part.credential_path.repository
    else:
        repository = part

    env, remove_env = ask_for_env(part, env, remove_env, ask_for_more=False)
    keys = part.get_env_file(credo.crypto)
    if keys.changed:
        repository.add_change("Capturing environment variables", [part.environment_location])

def do_env(credo, all_accounts=False, all_users=False, find_user=False, **kwargs):
    """display environment variables only"""
    part = credo.find_credential_path_part(all_accounts=all_accounts, all_users=all_users, find_user=find_user)
    if hasattr(part, "credential_path"):
        repository = part.credential_path.repository
    else:
        repository = part
    do_exports(credo, chosen=part, repository=repository)

def do_synchronize(credo, **kwargs):
    """Just synchronize some repo"""
    repo_name, location = credo.find_one_repository(want_new=False)
    structure.repository.synchronize(repo_name, location, credo.crypto)

def do_exec(credo, command, **kwargs):
    """Exec some command with aws credentials in the environment"""
    environment = dict(os.environ)
    for key, val in credo.chosen.shell_exports():
        if val == "CREDO_UNSET":
            if key in environment:
                del environment[key]
        else:
            environment[key] = val
    os.execvpe(command[0], command, environment)
    credo.chosen.credential_path.repository.synchronize()

def do_rotate(credo, force=False, **kwargs):
    """Rotate some keys"""
    log.info("Doing a rotation")
    credo.make_chosen(rotate=True, invalidate_creds=force).credential_path.repository.synchronize()

def do_remote(credo, remote=None, version_with=None, **kwargs):
    """Setup remotes for some repository"""
    repo_name, location = credo.find_one_repository()
    structure.repository.configure(repo_name, location, credo.crypto, new_remote=remote, version_with=version_with)

def do_import(credo, source=False, half_life=None, **kwargs):
    """Import some creds"""
    structure, chains = credo.find_credentials(asker=ask_for_choice_or_new, want_new=True)
    creds = list(credo.credentials_from(structure, chains))[0]
    cred_path = creds.credential_path
    log.info("Making credentials for\trepo=%s\taccount=%s\tuser=%s", cred_path.repository.name, cred_path.account.name, cred_path.user.name)

    cred_path.repository.pub_key_syncer.sync()
    log.debug("Crypto has private keys %s", credo.crypto.private_key_fingerprints)
    log.debug("Crypto has public_keys %s", credo.crypto.public_key_fingerprints)

    if not credo.crypto.can_encrypt:
        raise CantEncrypt("No public keys to encrypt with", repo=cred_path.repository.name)
    if not credo.crypto.can_sign:
        log.error("Couldn't find any private keys matching your known public keys!")
        cred_path.repository.pub_key_syncer.sync(ask_anyway=True)
        if not credo.crypto.can_sign:
            raise CantSign("No private keys with matching public keys to sign with", repo=cred_path.repository.name)

    access_key, secret_key = ask_user_for_secrets(source=source)
    if half_life is None:
        half_life = ask_user_for_half_life(access_key)
    if isinstance(half_life, basestring) and not half_life.isdigit():
        if half_life == "hour":
            half_life = 60 * 60
        elif half_life == "day":
            half_life = 60 * 60 * 24
        elif half_life == "week":
            half_life = 60 * 60 * 24 * 7
        else:
            raise CredoError("Unknown half life value", half_life=half_life)
    iam_pair = IamPair(access_key, secret_key, half_life=half_life)

    # Make sure the iam pair is for the right place
    if not iam_pair.works:
        raise BadCredential("The credentials you just provided don't work....")

    account_id = cred_path.account.account_id(iam_pair=iam_pair)
    if iam_pair.ask_amazon_for_account() != account_id:
        raise BadCredential("The credentials you are importing are for a different account"
            , credentials_account_id=iam_pair.ask_amazon_for_account(), importing_into_account_name=cred_path.account.name, importing_into_account_id=account_id
            )

    username = cred_path.user.username(iam_pair=iam_pair)
    if iam_pair.ask_amazon_for_username() != username:
        raise BadCredential("The credentials you are importing are for a different user"
            , credentials_user=iam_pair.ask_amazon_for_username(), importing_into_user=username
            )

    creds.keys.add(iam_pair)
    creds.save()
    cred_path.repository.synchronize()

def do_showavailable(credo, force_show_all=False, collapse_if_one=True, **kwargs):
    """Show all what available repos, accounts and users we have"""
    structure, chains = credo.find_credentials(no_mask=force_show_all)

    fltrs = ()
    if not force_show_all:
        fltrs = [(key, val) for key, val in [("repo", credo.repo), ("account", credo.account), ("user", credo.user)] if val]
    print_list_of_tuples(fltrs, "Using the filters")

    headings = ["Repositories", "Accounts", "Users"]

    def chains_to_dict(structure, chains):
        """Turn the list of chains into a dictionary"""
        dct = {}
        for chain in chains:
            location, rest, last = chain[0], chain[1:-1], chain[-1]
            d = dct
            for part in rest:
                if part not in d:
                    d[part] = {}
                d = d[part]
            d[last] = lambda: list(credo.credentials_from(structure, [chain], complain_if_missing=True))[0]
        return dct

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
        if callable(cred):
            cred = cred()
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

    # Complain if no found chains
    if not chains:
        print "Didn't find any credential files"
        return

    # Special case if we only found one
    if collapse_if_one and len(chains) is 1:
        creds = list(credo.credentials_from(structure, chains, complain_if_missing=True))[0]
        cred_path = creds.credential_path
        fltr = [("repo", cred_path.repository.name), ("account", cred_path.account.name), ("user", cred_path.user.name)]
        print_list_of_tuples(fltr, "Only found one set of credentials")
        display_creds(creds)
        return

    # Or just do them all if found more than one
    root = chains_to_dict(structure, chains)
    result = get_displayable(root, headings)
    display_result(result)

