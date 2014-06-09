from credo.errors import BadConfigFile, BadSSHKey, BadCredentialSource, CredoProgrammerError, UserQuit

import ConfigParser
import getpass
import logging
import keyring
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
                print >> sys.stderr, "{0}) {1}".format(num, val)
        elif isinstance(message, list):
            for msg in message:
                print >> sys.stderr, msg
        else:
            print >> sys.stderr, message

    if prompt:
        sys.stderr.write(str(prompt))
        sys.stderr.flush()

    try:
        if password:
            return getpass.getpass("")
        else:
            return raw_input()
    except KeyboardInterrupt:
        raise UserQuit()
    except EOFError:
        raise UserQuit()

def ask_for_choice(message, choices):
    """Ask for a value from some choices"""
    mapped = dict(enumerate(sorted(choices)))
    no_value = True
    while no_value:
        response = get_response(message, "Please choose a value from the following", mapped)

        if response is None or not response.isdigit() or int(response) not in mapped:
            print >> sys.stderr, "Please choose a valid response ({0} is not valid)".format(response)
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
                print >> sys.stderr, "Please choose a valid response ({0} is not valid)".format(response)
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
    }

def ask_user_for_secrets(source=None):
    """Ask the user for access_key and secret_key"""
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
        parser = ConfigParser.SafeConfigParser()
        aws_location = os.path.expanduser("~/.aws/config")
        boto_location = os.path.expanduser("~/.boto")

        if source == secret_sources["aws_config"] and not os.path.exists(aws_location):
            raise BadCredentialSource("Couldn't find the aws config", location=aws_location)
        if source == secret_sources["boto_config"] and not os.path.exists(boto_location):
            raise BadCredentialSource("Couldn't find the boto config", location=boto_location)

        if secret_sources["boto_location"] in (val, source):
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
            keyring_name = parser.get(section, 'keyring')
            secret_key = keyring.get_password(keyring_name, access_key)
    else:
        raise CredoProgrammerError("Not possible to reach this point", source=source)

    return access_key, secret_key

def ask_for_public_keys(remote=None):
    """
    Get keys from the user (urls, pems, locations)
    Where locations is a map of {<pem>: <location>} for when we know the location
    """
    urls = []
    pems = []
    locations = {}

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
        choice = ask_for_choice_or_new("Do you want to use a url to get public keys for this repository?", [no_choice, suggestion_choice])

    while True:
        if choice == no_choice:
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
        available = [os.path.join(ssh_folder, filename) for filename in os.listdir(ssh_folder) if filename.endswith(".pub")]
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
        if pems:
            question = "any more"
            no_choice = "No more"

        choice = ask_for_choice_or_new("Do you want to add {0} public pem lines?".format(question), [no_choice] + public_key_fingerprints.keys())
        if choice == no_choice:
            break
        elif choice in public_key_fingerprints:
            pem = public_key_pems[choice]
            locations[pem] = location
            pems.append(public_key_pems[choice])
            fingerprint = public_key_fingerprints[choice]
            del public_key_pems[choice]
            del public_key_fingerprints[choice]
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

    while True:
        choice = ask_for_choice_or_new("What half life do you want for this key? ({0})".format(access_key), [hour_choice, day_choice, week_choice])

        if choice == hour_choice:
            return 3600
        elif choice == day_choice:
            return 3600 * 24
        elif choice == week_choice:
            return 3600 * 24 * 7
        else:
            if not choice.isdigit():
                print >> sys.stderr, "Please enter an integer representing the number of seconds in the half life"
            else:
                return int(choice)

