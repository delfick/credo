from __future__ import print_function

from credo.errors import BadConfigFile, BadSSHKey, BadCredentialSource, ProgrammerError, UserQuit

from six.moves import configparser, input
from collections import OrderedDict
from itertools import chain
import getpass
import logging
import boto
import sys
import os

log = logging.getLogger("credo.asker")

def get_response(*messages, **kwargs):
    """Get us a response from the user"""
    password = kwargs.get("password", False)
    if password:
        prompt = kwargs.get("prompt", ":")
    else:
        prompt = kwargs.get("prompt", ": ")

    for message in messages:
        if isinstance(message, dict):
            for num, val in message.items():
                print("{0}) {1}".format(num, val), file=sys.stderr)
        elif isinstance(message, list):
            for msg in message:
                print(msg, file=sys.stderr)
        else:
            print(message, file=sys.stderr)

    if prompt:
        sys.stderr.write(str(prompt))
        sys.stderr.flush()

    try:
        if password:
            return getpass.getpass(" ")
        else:
            return input() or kwargs.get("default", "")
    except KeyboardInterrupt:
        raise UserQuit()
    except EOFError:
        raise UserQuit()

def ask_for_choice(message, choices):
    """Ask for a value from some choices"""
    mapped = OrderedDict(enumerate(choices))
    no_value = True
    while no_value:
        response = get_response(message, "Please choose a value from the following", mapped)

        if response is None or not response.isdigit() or int(response) not in mapped:
            print("Please choose a valid response ({0} is not valid)".format(response), file=sys.stderr)
        else:
            no_value = False
            return mapped[int(response)]

def ask_for_choice_or_new(needed, choices):
    mapped = dict(zip(range(len(choices)), choices))
    while True:
        if mapped:
            maximum = max(mapped.keys())
            response = get_response(
                  "Choose a {0}".format(needed), "Please choose a value from the following"
                , mapped, {maximum+1: "Make your own value"}
                )

            if response is None or not response.isdigit() or int(response) < 0 or int(response) > maximum + 1:
                print("Please choose a valid response ({0} is not valid)".format(response), file=sys.stderr)
                continue
            else:
                response = int(response)
                if response in mapped:
                    return mapped[response]

            return get_response(prompt="Enter your custom value: ")
        else:
            return get_response("Choose a {0}".format(needed), prompt="Enter your custom value: ")

secret_sources = {
      "specified": "Specify your own value"
    , "aws_config": "Your awscli config file"
    , "boto_config": "Your boto config file"
    , "environment": "Your current environment"
    , "saml_provider": "One of your registered saml providers"
    }

def ask_user_for_secrets(credo, source=None):
    """Ask the user for access_key and secret_key"""
    typ = "amazon"
    choices = []
    access_key_name = "AWS_ACCESS_KEY_ID"
    secret_key_name = "AWS_SECRET_ACCESS_KEY"

    environment = os.environ

    if access_key_name in environment and secret_key_name in environment:
        choices.append(secret_sources["environment"])

    if os.path.exists(os.path.expanduser("~/.aws/config")):
        choices.append(secret_sources["aws_config"])

    if os.path.exists(os.path.expanduser("~/.boto")):
        choices.append(secret_sources["boto_config"])

    if credo.providers:
        choices.extend(["Saml provider '{0}'".format(provider) for provider in credo.providers])

    val = None
    if not source:
        if choices:
            val = ask_for_choice("Method of getting credentials", choices + [secret_sources["specified"]])
        else:
            val = secret_sources["specified"]
    else:
        if source not in secret_sources.keys() and source not in secret_sources.values():
            raise BadCredentialSource("Unknown credential source", source=source)

        if source in secret_sources:
            source = secret_sources[source]

        log.info("Getting credentials from %s", source)

    if secret_sources["specified"] in (val, source):
        access_key = get_response(prompt="Access key: ")
        secret_key = get_response(prompt="Secret key: ")

    elif secret_sources["environment"] in (val, source):
        if access_key_name not in environment or secret_key_name not in environment:
            raise BadCredentialSource("Couldn't find environment variables for {0} and {1}".format(access_key_name, secret_key_name))
        access_key = environment[access_key_name]
        secret_key = environment[secret_key_name]

    elif secret_sources["boto_config"] in (val, source) or secret_sources["aws_config"] in (val, source):
        parser = configparser.SafeConfigParser()
        aws_location = os.path.expanduser("~/.aws/config")
        boto_location = os.path.expanduser("~/.boto")

        if source == secret_sources["aws_config"] and not os.path.exists(aws_location):
            raise BadCredentialSource("Couldn't find the aws config", location=aws_location)
        if source == secret_sources["boto_config"] and not os.path.exists(boto_location):
            raise BadCredentialSource("Couldn't find the boto config", location=boto_location)

        if secret_sources["boto_config"] in (val, source):
            location = boto_location
        else:
            location = aws_location

        # Read it in
        parser.read(location)

        # Find possilbe sections
        sections = []
        for section in boto.config.sections():
            if section in ("Credentials", "default"):
                sections.append(section)

            elif section.startswith("profile "):
                sections.append(section)

        # Get sections that definitely have secrets
        sections_with_secrets = []
        for section in sections:
            if parser.has_option(section, "aws_access_key_id") and (parser.has_option(section, "aws_secret_access_key") or parser.has_option(section, "keyring")):
                sections_with_secrets.append(section)

        if not sections:
            raise BadConfigFile("No secrets to be found in the amazon config file", location=location)
        elif len(sections) == 1:
            section = sections[0]
        else:
            section = ask_for_choice("Which section to use?", sections)

        access_key = parser.get(section, "aws_access_key_id")
        if parser.has_option(section, "aws_secret_access_key"):
            secret_key = parser.get(section, "aws_secret_access_key")
        else:
            import keyring
            keyring_name = parser.get(section, 'keyring')
            secret_key = keyring.get_password(keyring_name, access_key)

    elif secret_sources["saml_provider"] in (val, source) or "Saml provider" in val:
        return "saml", "idp.realestate.com.au"

    else:
        raise ProgrammerError("Not possible to reach this point", source=source)

    return typ, (access_key, secret_key)

def ask_for_public_keys(remote=None, known_private_key_fingerprints=None):
    """
    Get keys from the user (urls, pems, locations)
    Where locations is a map of {<pem>: <location>} for when we know the location
    """
    urls = []
    pems = []
    locations = {}

    quit_choice = "Quit"
    no_choice = "No thanks"
    choice = no_choice

    if remote:
        if "@" in remote:
            _, path = remote.split("@", 1)
        if ":" in path:
            domain, path = path.split(":", 1)
        if "/" in path:
            username, path = path.split("/", 1)
        else:
            username = path

        suggestion = "https://{0}/{1}.keys".format(domain, username)
        suggestion_choice = "Use {0}".format(suggestion)
        choice = ask_for_choice_or_new("Do you want to use a url to get public keys for this repository?", [quit_choice, no_choice, suggestion_choice])

    while True:
        if choice == quit_choice:
            raise UserQuit()
        elif choice == no_choice:
            break
        elif choice == suggestion_choice:
            urls.append(suggestion)
        else:
            urls.append(choice)

        no_choice = "No more"
        choice = ask_for_choice_or_new("Do you to use any other urls for public keys?", [no_choice])

    public_key_pems = {}
    public_key_locations = {}
    public_key_fingerprints = {}

    from credo.crypto import KeyCollection
    collection = KeyCollection()
    ssh_folder = os.path.expanduser("~/.ssh")

    if os.path.exists(ssh_folder):
        available = list(chain.from_iterable(
            [ os.path.join(root, filename) for filename in files if filename.endswith(".pub")]
            for root, _, files in  os.walk(ssh_folder)
        ))

        for location in available:
            try:
                with open(location) as fle:
                    contents = fle.read()
                fingerprint = collection.add_public_key(contents)
                public_key_pems[location] = contents
                public_key_locations[fingerprint] = location
                public_key_fingerprints[location] = fingerprint
            except OSError as err:
                log.warning("Couldn't read %s (%s)", location, err)
            except BadSSHKey as err:
                log.warning("%s is not a valid public key (%s)", location)

    while True:
        question = "any"
        no_choice = "No thanks"
        quit_choice = "Quit"
        if pems:
            question = "any more"
            no_choice = "No more"

        public_key_fingerprints_choices = {}
        for location, fingerprint in public_key_fingerprints.items():
            public_key_fingerprints_choices["{0} ({1})".format(location, fingerprint)] = location

        if known_private_key_fingerprints:
            log.info("Know the following private keys\n\t%s", "\n\t".join(v.decode('utf-8') for v in known_private_key_fingerprints))
        choice = ask_for_choice_or_new("Do you want to add {0} public pem lines?".format(question), [quit_choice, no_choice] + sorted(public_key_fingerprints_choices.keys()))
        if choice == quit_choice:
            raise UserQuit()
        elif choice == no_choice:
            break
        elif choice in public_key_fingerprints_choices:
            choice = public_key_fingerprints_choices[choice]
            pem = public_key_pems[choice]
            locations[pem] = location
            pems.append(public_key_pems[choice])
            fingerprint = public_key_fingerprints[choice]
            del public_key_pems[choice]
            del public_key_fingerprints[choice]
            if fingerprint in public_key_locations:
                del public_key_locations[fingerprint]
        else:
            try:
                fingerprint = collection.add_public_key(choice)
                pems.append(choice)
                location = public_key_locations.get(fingerprint)
                if location:
                    del public_key_locations[fingerprint]
                    del public_key_fingerprints[location]
            except BadSSHKey as err:
                log.warning("The key you entered is not a valid public key (%s)", err)

    return urls, pems, locations

def ask_user_for_half_life(access_key):
    """Ask the user for a half life value"""
    day_choice = "One day"
    hour_choice = "One hour"
    week_choice = "One week"
    forever_choice = "forever"

    while True:
        choice = ask_for_choice_or_new("What half life do you want for this key? ({0})".format(access_key), [hour_choice, day_choice, week_choice, forever_choice])

        if choice == hour_choice:
            return 3600
        elif choice == day_choice:
            return 3600 * 24
        elif choice == week_choice:
            return 3600 * 24 * 7
        elif choice == forever_choice:
            return -1
        else:
            if not choice.isdigit():
                print("Please enter an integer representing the number of seconds in the half life", file=sys.stderr)
            else:
                return int(choice)

def ask_for_ssh_key_folders(already_have=None):
    """Ask for folders where we can find private keys"""
    if already_have is None:
        already_have = []
    originally_already_have = list(already_have)
    home_ssh = os.path.expanduser("~/.ssh")

    result = []
    while True:
        quit_choice = "Quit"
        choices = [quit_choice]

        retry_choice = None
        if originally_already_have:
            retry_choice = "I've added more keys to existing folders ({0}), try those again".format(", ".join(originally_already_have))
            choices.append(retry_choice)

        retry_home_choice = None
        if not os.path.exists(home_ssh):
            retry_home_choice = "I've used ssh-keygen, look for keys again"
            choices.append(retry_home_choice)

        if os.path.exists(home_ssh) and home_ssh not in already_have:
            choices.append(home_ssh)

        choice = ask_for_choice_or_new("Where can we find private ssh keys?", choices=choices)
        if choice == quit_choice:
            raise UserQuit()
        elif choice == retry_choice:
            break
        elif choice == retry_home_choice:
            if not os.path.exists(home_ssh):
                log.error("You say you've used ssh-keygen, but ~/.ssh (%s) doesn't exist....", home_ssh)
                continue
            else:
                if home_ssh not in result:
                    result.append(home_ssh)
                return result
        else:
            if not os.path.exists(choice):
                log.error("Provided folder doesn't exist!\tfolder=%s", choice)
            else:
                if choice in already_have:
                    log.info("Already have that folder!\tfolder=%s", choice)
                else:
                    result.append(choice)
                    already_have.append(choice)

        more_choice = "More folders"
        enough_choice = "No more folders"
        choice = ask_for_choice("What next?", choices=[quit_choice, more_choice, enough_choice])
        if choice == quit_choice:
            raise UserQuit()
        elif choice == enough_choice:
            break

    return result

def ask_for_env(part, env, remove_env, ask_for_more=False):
    """Ask the user for environment variables to store"""
    if env:
        part.add_env(env, part.crypto)
    if remove_env:
        part.remove_env(remove_env, part.crypto)

    if ask_for_more or not env:
        env_file = part.get_env_file(part.crypto)
        while True:
            stop_choice = "Stop specifying environment variables"
            show_choice = "Show what we currently have stored"
            add_new_choice = "Create new environment variable"
            uncapture_choice = "Uncapture a variable"
            use_existing_choice = "Use existing environment variable"

            choices = [stop_choice, show_choice, add_new_choice, use_existing_choice]
            if any(env_file.keys):
                choices.append(uncapture_choice)
                print("Captured env variables for [{0}]".format(", ".join('"{0}"'.format(key) for key in env_file.keys.keys())), file=sys.stderr)

            choice = ask_for_choice("What to do?", choices=choices)
            if choice == stop_choice:
                break
            elif choice == show_choice:
                print("", file=sys.stderr)
                for key, val in env_file.keys.items():
                    print("{0} = {1}".format(key, val), file=sys.stderr)
                    print("---", file=sys.stderr)
                    print("", file=sys.stderr)

                if hasattr(part, "parent_path_part"):
                    shell_exports = part.parent_path_part.shell_exports()
                    if shell_exports:
                        print("=" * 80)
                        print("Overriding")
                        print("-" * 40)
                        print("")
                        for key, val in shell_exports:
                            print("{0} = {1}".format(key, val), file=sys.stderr)
                            print("===", file=sys.stderr)
                            print("", file=sys.stderr)

            elif choice == add_new_choice:
                name = get_response(prompt="Name: ")
                value = get_response(prompt="Value: ")
                part.add_env([(name, value)], part.crypto)
            elif choice == use_existing_choice:
                name = get_response(prompt="Name: ")
                if name not in os.environ:
                    log.error("There is no environment variable called %s", name)
                else:
                    part.add_env([(name, os.environ[name])], part.crypto)
            elif choice == uncapture_choice:
                ignore_choice = "Actually, I don't want to uncapture any"
                choices = [ignore_choice] + env_file.keys.keys()
                choice = ask_for_choice("Which do you want to remove?", choices=choices)
                if choice != ignore_choice:
                    part.remove_env([choice], part.crypto)

    return env, remove_env

def ask_user_for_saml(credo, action=None, provider=None):
    """Ask the user for saml providers"""
    if action not in (None, "delete", "add", "show"):
        raise ProgrammerError("Given a saml action other than delete or add", got=action)

    first = True
    supplied_action = action
    while True:
        quit_action = "Quit"
        add_action = "Add a provider"
        show_action = "Show providers"
        delete_action = "Delete a provider"
        no_more_action = "No more"

        if supplied_action:
            action = {"add": add_action, "delete": delete_action, "show": show_action}[supplied_action]

        if not supplied_action:
            question = "Do you want to add a provider or remove a provider?"
            choices = [quit_action]
            if not first:
                choices.append(no_more_action)

            if credo.providers:
                question = "{0} or remove a provider?".format(question)
                choices.extend([add_action, show_action, delete_action])
            else:
                question = "{0}?".format(question)
                choices.append(add_action)

            action = ask_for_choice(question, choices)

        if action == no_more_action:
            return

        elif action == show_action:
            print("Current providers are:")
            for provider in credo.providers:
                print("\t{0}".format(provider))

        elif action == add_action:
            if not provider:
                provider = get_response("Saml provider")

            credo.register_saml_provider(provider)
            if supplied_action:
                return

        elif action == delete_action:
            if not credo.providers:
                log.info("No providers to delete!")
                if supplied_action:
                    return

            removing = provider
            if not removing:
                removing = ask_for_choice("Which provider do you want to remove?", choices=credo.providers)

            credo.remove_saml_provider(removing)
            if supplied_action:
                return

        elif action == quit_action:
            raise UserQuit()

        # Reset for next loop iteration
        first = False
        action = None
        provider = None
        supplied_action = False

