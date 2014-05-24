Credo
=====

The python version of Credulous

Credo is a credential management program for amazon credentials written
in golang. It can be found at https://github.com/realestate-com-au/credulous

Usage
-----

Import some keys::

    credo import

Export those keys to your environment::

    `credo display`
    # Display prints out the required environment exports
    # The backticks means your shell will run those exports

Or execute a command with those keys::

    credo exec bash -c 'echo $AWS_ACCESS_KEY_ID'

All credo commands take::

    credo <credo_options> <|action|> <action_options>

Where <credo_options> help filter out the different keys you have stored.

Upon ambiguity credo will ask you questions and tries it's best to provide cli
options to remove that ambiguity when you use the command.

For example, when importing keys, credo will look for environment variables,
boto configuration, aws configuration or allow you to specify your own keys.
It will only prompt you for the sources it finds, or you can say what source
you want::

    credo import --source environment

Layout
------

Credo will layout your credentials using the following folder structure::

    ~/.credo/
        config.json

        repos/
            <repository>/
                <account>/
                    account_id
                    <user>/
                        credentials.json

Where ``config.json`` has some configuration for credo, ``account_id`` holds
the id of the amazon account represented by that folder, and ``credentials.json``
has amazon credential for that user and account.

The ``account_id`` is a file with one line containing
"<account_id>,<fingerprint>,<signature>" where the fingerprint and signature is
used to verify that one of your private keys recorded this account_id. This is
to ensure that the credentials found in credentials.json do actually belong to
this account.

The ``credentials.json`` contains the credentials encrypted with each public key
it knows about and a signature used to verify that the credentials were written
using one of you private keys against a particular account and user.

This means you may only add credentials using one of your private keys.

Installation
------------

Use pip!::

    pip install credo

Or if you're developing it::

    pip install -e .
    pip install -e ".[tests]"

Tests
-----

Run the helpful script::

    ./test.sh

