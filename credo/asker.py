from credo.errors import BadConfigFile

import ConfigParser
import keyring
import boto
import sys
import os

def ask_for_choice(message, choices):
    """Ask for a value from some choices"""
    mapped = dict(enumerate(sorted(choices)))
    no_value = True
    while no_value:
        print >> sys.stderr, message
        print >> sys.stderr, "Please choose a value from the following"
        for num, val in mapped.items():
            print >> sys.stderr, "{0}) {1}".format(num, val)

        sys.stderr.write(": ")
        sys.stderr.flush()
        response = raw_input()

        if response is None or not response.isdigit() or int(response) not in mapped:
            print >> sys.stderr, "Please choose a valid response ({0} is not valid)".format(response)
        else:
            no_value = False
            return mapped[int(response)]

def ask_for_choice_or_new(needed, choices):
    mapped = dict(enumerate(sorted(choices)))
    no_value = True
    while no_value:
        print >> sys.stderr, "Choose a {0}".format(needed)
        if mapped:
            maximum = max(mapped.keys())
            print >> sys.stderr, "Please choose a value from the following"
            num = -1
            for num, val in mapped.items():
                print >> sys.stderr, "{0}) {1}".format(num, val)
            print >> sys.stderr, "{0}) {1}".format(num+1, "Make your own value")

            sys.stderr.write(": ")
            sys.stderr.flush()
            response = raw_input()

            if response is None or not response.isdigit() or int(response) < 0 or int(response) > maximum + 1:
                print >> sys.stderr, "Please choose a valid response ({0} is not valid)".format(response)
            else:
                no_value = False
                response = int(response)
                if response in mapped:
                    return mapped[response]
        else:
            no_value = False

        if not no_value:
            sys.stderr.write("Enter your custom value: ")
            sys.stderr.flush()
            return raw_input()

def ask_user_for_secrets():
    """Ask the user for access_key and secret_key"""
    choices = []
    access_key_name = "AWS_ACCESS_KEY_ID"
    secret_key_name = "AWS_SECRET_ACCESS_KEY"

    environment = os.environ
    environment_choice = "From your current environment"
    aws_config_file_choice = "From awscli config file"
    boto_config_file_choice = "From your boto config file"

    if access_key_name in environment and secret_key_name in environment:
        choices.append(environment_choice)

    if os.path.exists(os.path.expanduser("~/.aws/config")):
        choices.append(aws_config_file_choice)

    if os.path.exists(os.path.expanduser("~/.boto")):
        choices.append(boto_config_file_choice)

    if choices:
        val = ask_for_choice("Method of getting keys", choices + ["specify"])
    else:
        val = "specify"

    if val == "specify":
        access_key = raw_input("Access key: ")
        secret_key = raw_input("Secret key: ")
    elif val == environment_choice:
        access_key = os.environ["AWS_ACCESS_KEY_ID"]
        secret_key = os.environ["AWS_SECRET_ACCESS_KEY"]
    elif val in (aws_config_file_choice, boto_config_file_choice):
        parser = ConfigParser.SafeConfigParser()
        if val == aws_config_file_choice:
            location = os.path.expanduser("~/.aws/config")
        elif val == boto_config_file_choice:
            location = os.path.expanduser("~/.boto")

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

    return access_key, secret_key

