from credo.asker import ask_user_for_secrets, ask_for_choice_or_new, ask_for_env, ask_user_for_saml, get_response, ask_for_choice
from credo.errors import CantEncrypt, CantSign, BadCredential, ProgrammerError, SamlNotAuthorized, CredoError
from credo.helper import print_list_of_tuples, make_export_commands, normalise_half_life
from credo.structure.credentials import SamlCredentials
from credo.amazon import IamPair, IamSaml
from credo.server import Server
from credo import structure

from textwrap import dedent
import pkg_resources
import platform
import requests
import logging
import base64
import pickle
import shutil
import json
import sys
import os

log = logging.getLogger("credo.actions")

def do_serve(credo, port=80, host="169.254.169.254", **kwargs):
    Server(host, port, credo).start()

def do_switch(credo, port=80, host="169.254.169.254", **kwargs):
    url = "http://{0}:{1}/latest/meta-data/switch/".format(host, port)
    chosen = credo._chosen = credo.make_chosen(rotate=False)
    if not isinstance(chosen, SamlCredentials):
        raise CredoError("Switch only supports idp roles")

    request = {"credentials": chosen}
    while True:
        response = requests.post(url, data=pickle.dumps(request), headers={"Content-Type": "application/octet-stream"})
        if response.status_code == 500:
            error = response.json()["error"]
            if error in ("NEED_AUTH", "BAD_PASSWORD"):
                if error == "BAD_PASSWORD":
                    log.error("Password was incorrect")
                password = get_response("Password for idp user {0}".format(chosen.keys.idp_username), password=True)
                request["basic_auth"] = base64.b64encode("{0}:{1}".format(chosen.keys.idp_username, password).encode('utf-8'))
            else:
                break
        else:
            break

    print("{0}: {1}".format(response.status_code, response.text))

def do_current(credo, **kwargs):
    """Print out what user is currently in our environment"""
    if "AWS_ACCESS_KEY_ID" not in os.environ or "AWS_SECRET_ACCESS_KEY" not in os.environ:
        print("There are currently no credentials in your environment!")
    else:
        iam_pair = IamPair.from_environment()
        print("Asking amazon for details")
        if not iam_pair.works:
            print("Your current credentials are not valid....")
        else:
            aliases = iam_pair.ask_amazon_for_account_aliases()
            if not aliases:
                aliases = ["<no_account_alias>"]
            print("You are currently \"{0}\" from \"{1}\" (account {2})".format(
                iam_pair.ask_amazon_for_username(), aliases[0], iam_pair.ask_amazon_for_account()
                ))

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

def do_exports(credo, chosen=None, repository=None, half_life=None, **kwargs):
    """Just print out the chosen creds"""
    half_life = normalise_half_life(half_life or getattr(credo, "half_life", None))

    if chosen is None:
        chosen = credo._chosen = credo.make_chosen(rotate=True, half_life=half_life)

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

def do_exec(credo, command, half_life=None, **kwargs):
    """Exec some command with aws credentials in the environment"""
    half_life = normalise_half_life(half_life or getattr(credo, "half_life", None))
    credo._chosen = credo.make_chosen(rotate=True, half_life=half_life)

    environment = dict(os.environ)
    for key, val in credo.chosen.shell_exports():
        if val == "CREDO_UNSET":
            if key in environment:
                del environment[key]
        else:
            environment[key] = val
    os.execvpe(command[0], command, environment)
    credo.chosen.credential_path.repository.synchronize()

def do_rotate(credo, force=False, half_life=None, **kwargs):
    """Rotate some keys"""
    log.info("Doing a rotation")
    half_life = normalise_half_life(half_life or getattr(credo, "half_life", None))
    credo.make_chosen(rotate=True, invalidate_creds=force, half_life=half_life).credential_path.repository.synchronize()

def do_remote(credo, remote=None, version_with=None, **kwargs):
    """Setup remotes for some repository"""
    repo_name, location = credo.find_one_repository()
    structure.repository.configure(repo_name, location, credo.crypto, new_remote=remote, version_with=version_with)

def do_import(credo, source=False, half_life=None, **kwargs):
    """Import some creds"""
    typ, info = ask_user_for_secrets(credo, source=source)
    if typ == "amazon":
        access_key, secret_key = info
        iam_pair = IamPair(access_key, secret_key, half_life=half_life)

        if not iam_pair.works:
            raise BadCredential("The credentials you just provided don't work....")
        half_life = normalise_half_life(half_life, access_key) or getattr(credo, "half_life", None)
        iam_pair.set_half_life(half_life)
        iam_pair._changed = False

    elif typ == "saml":
        access_key = None

        # Keep asking for username and password until they give one
        while True:
            idp_username = get_response("Idp username", default=os.environ.get("USER"))
            idp_password = get_response("Idp password", password=True)
            iam_pair = IamSaml(info, idp_username, idp_password, half_life=half_life)
            try:
                arns = iam_pair.arns
            except SamlNotAuthorized:
                continue

            saml_account = ask_for_choice("Which account do you want to use?", choices=sorted(arns, key=lambda a: a.role_arn))
            break
    else:
        raise ProgrammerError("Unknown credential type {0}".format(typ))

    structure, chains = credo.find_credentials(asker=ask_for_choice_or_new, want_new=True)
    creds = list(credo.credentials_from(structure, chains, typ=typ))[0]
    cred_path = creds.credential_path
    log.info("Making credentials for\trepo=%s\taccount=%s\tuser=%s", cred_path.repository.name, cred_path.account.name, cred_path.user.name)

    if typ != "saml":
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

    if typ == "amazon":
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
    else:
        contents = creds.contents
        contents.keys["provider"] = info
        contents.keys["role"] = saml_account.encrypted_values()
        contents.keys["idp_username"] = idp_username

    creds.save(half_life=half_life)
    cred_path.repository.synchronize()

def do_register_saml(credo, provider=None, **kwargs):
    """Register a saml provider"""
    if provider:
        credo.register_saml_provider(provider)
    else:
        ask_user_for_saml(credo)

def do_output_extension(credo, output, **kwargs):
    """Output the Chrome extension for the metadata magic server."""
    source = pkg_resources.resource_filename("credo", "ext")
    try:
        shutil.copytree(source, output)
    except OSError as error:
        raise CredoError("Failed to copy directory", source=source, output=output, error=error)

    print(dedent("""
        Congratulations, you know have the extension.
        - Please go into Chrome.
        - Go to chrome://extensions.
        - Enable developer mode.
        - Load unpacked extension.
            - Choose {0}
    """.format(output)))

def do_print_shell_function(credo, virtualenv=None, **kwargs):
    """Print the shell function to add to your environment."""

    if virtualenv is None:
        virtualenv = os.path.abspath(
                os.path.join( os.path.dirname(sys.argv[0]), "../")
            )

    mac_setup = """
        addr="169.254.169.254";
        loopback_interface="lo0";
        if ! ifconfig ${loopback_interface} | grep ${addr} > /dev/null; then;
            echo "creating $addr alias";
            sudo ifconfig lo0 alias $addr;
            plist=/Library/LaunchDaemons/delfick.credo.fake_metadata.plist;
            for action in unload load; do;
                sudo launchctl $action $plist;
            done;
        fi;
    """

    linux_setup = """
        addr="169.254.169.254";
        if ! ip route get $addr | grep "dev lo"; then
            echo "creating $addr alias";
            sudo ip addr add $addr dev lo
        fi;
    """

    if os.name == "posix":
        if platform.system() == "Darwin":
            setup = mac_setup
        else:
            setup = linux_setup
    else:
        setup = ""

    setup = "\n    ".join(line for line in setup.split('\n'))

    print(dedent("""
        Add the following to your shrc file (~/.bashrc, ~/.zshrc)

        ======================================================
        credo () {{
            {1}
            if {0}/bin/credo sourceable $@; then
                output=$({0}/bin/credo $@);
                if (($? == 0)); then
                    echo "$output" > /tmp/lolz;
                    source /tmp/lolz;
                else
                    echo "$output";
                fi;
            else
                {0}/bin/credo $@;
            fi
        }}
        switch () {{
            if [[ -z $1 ]]; then
                credo switch
            else
                credo --account $1 switch
            fi
        }}
        ======================================================
    """.format(virtualenv, setup)))

def do_create_launch_daemon(credo, virtualenv=None, **kwargs):
    """Write the LaunchConfig plist file."""
    output_file = "/Library/LaunchDaemons/delfick.credo.fake_metadata.plist"
    config_location = os.path.expanduser("~/.credo/config.json")

    if virtualenv == None:
        virtualenv = os.path.abspath(
                os.path.join( os.path.dirname(sys.argv[0]), "../")
            )

    if os.path.exists(output_file):
        print("File already exists! ({0})".format(output_file))
        return

    with open(output_file, "w") as fle:
        fle.write(dedent("""
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                    <key>Label</key>
                    <string>delfick.credo.fake_metadata</string>
                    <key>ProgramArguments</key>
                    <array>
                            <string>{0}/bin/credo</string>
                            <string>--config</string>
                            <string>{1}</string>
                            <string>serve</string>
                    </array>
                    <key>RunAtLoad</key>
                    <true/>
                    <key>UserName</key>
                    <string>root</string>
                    <key>EnvironmentVariables</key>
                    <dict>
                        <key>HOME</key>
                        <string>{2}</string>
                    </dict>
                    <key>StandardOutPath</key>
                    <string>/var/log/credo/out.log</string>
                    <key>StandardErrorPath</key>
                    <string>/var/log/credo/err.log</string>
            </dict>
            </plist>
        """.format(virtualenv, config_location, os.path.expanduser("~"))))

    print(dedent("""
        LaunchDaemon has been written to {0}.

        To load the daemon use the following command:

           $ launchctl load {0}

        If there are every any problems, try:

           $ launchctl unload {0}
           $ launchctl load {0}

    """.format(output_file)))

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
            rest, last = chain[1:-1], chain[-1]
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
            print("{0}{1}".format(indent * 3, line))

    def display_result(result):
        """Display the result from get_displayable"""
        heading, children = result
        print("")
        print(heading)
        for child, values in children.items():
            print("")
            print(child)
            if isinstance(values, list) or isinstance(values, tuple) or isinstance(values, dict):
                display_result(values)
            elif values:
                display_creds(values, "    ")

    # Complain if no found chains
    if not chains:
        print("Didn't find any credential files")
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

