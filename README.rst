Credo
=====

The python implementation of Credulous (https://github.com/realestate-com-au/credulous)

Essentially, it's a credential management program written with amazon
credentials in mind. It uses your ssh key pairs to keep your credentials
encrypted on disk until you need to use them.

Installation
------------

Use pip!::

    pip install credo_manager

Usage
-----

Import some keys::

    credo import

Export those keys to your environment::

    `credo exports`
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

The <credo_options> filter can be:

-u/--user <user>

    Where user is either the name of the user or ``user@account`` or
    ``user@account@repo``. Account and repo specified here will override the
    other filters

-a/--account <account>

    Where account is either the name of the account or ``account@repo``. Repo
    specified here will override anything in the --repo filter.

-r/--repo <repo>

    Where repo is the name of the repository.

Status
------

Currently Credo seems to work fine.

Though, I haven't written tests for the majority of it, so I'll make no
guarantees at the moment.

No tests means my implementation is a bit messier than I would like and it's
likely there are hidden bugs in some of the code that handles the corner cases
I don't see in my normal usage.

So until tests are written, this should be **considered alpha quality**.

Features
--------

Credo usage allows you to specify what you want to do via the cli and credo will
ask questions for any ambiguity it comes across.

credo exports
    Print out export lines for exporting the credentials

credo inject
    An alias for credo exports

    Credo inject will be registered as sourceable by the credo sourceable command

credo exec
    Run a command with credentials in the environment of that command

credo import
    Add credentials

credo rotate
    Rotate credentials

credo show
    Show what credentials credo is currently aware of

credo current
    Display the username, account alias and account id of the amazon credentials
    you currently have in your environment.

credo synchronize
    Make a repository synced with it's remote

credo capture
    Capture environment variables

credo env
    Display only environment variables that have been captured

credo unset
    Reset any environment variables credo has changed to what they were before
    credo set them

credo remote
    Allows you to edit the remote for some repository. All commands will add
    changes as they are made and will try to synchronise with any remote that is
    set.

    Note that this functionality is extremely rudimentary

    Versioning without a remote
        Makes it a git repository without adding any remote

    No versioning at all
        Removes any .git folder in that repository

    Versioning with some remote
        If not already versioned, makes it a git folder, and makes sure we have
        the remote set as specified.

credo sourceable <argv>
    Exits with 0 (yes) or 1 (no) to say whether the output of running credo with
    the specified arguments should be sourced into the running shell.

    See the Advanced Usage section to see this in use.

    Note that if you give "--no-sourcing" as an action option, then sourceable
    will say this command should not be sourced

credo register_saml
    Used to register an idp provider so that when you do an inject it is
    available as a source of credentials

credo serve
    Serve a fake metadata service. This needs to be run as root so that we can bind
    to port 80 on 169.254.169.254.

    <look further down for more instructions>

credo switch
    Tell the fake metadata service which credentials to use. It behaves just like ``inject``.

credo print_shell_function
    Dump some helper shell functions that you can add into your shrc.

credo output_extension
    Where to save your Chrome Extension.

credo create_launch_daemon
    Task to generate a launchd.plist configuration.

It also does:

* Stores your credentials so that you have repositories of users in particular
  accounts.
* Import from environment, ~/.boto, ~/.aws/config or values you specify
* Knows about profiles in ~/.boto and ~/.aws/config
* Uses signatures to ensure that only you ever write encrypted credentials
* Uses signatures to ensure that the credentials you load is for the account
  that you think it is for
* Copes when keys are no longer usable.
* Lets you specify urls or just pem_data for the public keys per repository and
  caches what it finds
* Minimises the number of times you need to enter a password for your private
  keys
* Tries it's best to find situations it can't handle and display nice error
  messages to the screen
* Tries to be informative about what is happening
* Rotate keys automatically
* Can capture environment variables per repository, account and user
* Retrieve credentials from a saml based identity provider

Rotation
--------

Credo will do key rotation similar to credulous.

It does this by recording a "half_life" for each key, which is the number of
seconds since the creation of the key before it "rotates".

Rotation means the other key (amazon only allows you to have two keys) gets
deleted and a new key is created.

Also, if a key is older than twice it's half life, it's deleted.

When credo chooses a key to use, it will always use the youngest key.

Credo also handles the following situations:

* Both keys are no longer working
* There is a key in amazon credo doesn't know about
  * Credo asks if you want to delete it or tell it the secret key
* Both keys credo knows about are past their half life
* Both keys credo knows about are both past twice their half life
* The keys credo knows about don't need to be deleted or rotated

Layout
------

Credo will layout your credentials using the following folder structure::

    ~/.credo/
        config.json

        repos/
            <repository>/
                keys
                env.json
                <account>/
                    account_id
                    env.json
                    <user>/
                        username
                        env.json
                        credentials.json

Where ``config.json`` has some configuration for credo, ``account_id`` holds
the id of the amazon account represented by that folder, and ``credentials.json``
has amazon credential for that user and account.

The ``keys`` file holds the pems you want credo to encrypt details with. It is
signed by one of your private keys to ensure only your public keys are in this
file.

The ``account_id`` is a file with one line containing
"<account_id>,<fingerprint>,<signature>" where the fingerprint and signature is
used to verify that one of your private keys recorded this account_id under this
account and repository. This is to ensure that the credentials found in
credentials.json do actually belong to this account and repo.

The ``username`` is a file like the ``account_id`` but holds the amazon username
associated with this user, and a signature used to validate this name.

The ``credentials.json`` contains the credentials encrypted with each public key
it knows about and a signature used to verify that the credentials were written
using one of you private keys against a particular account and user.

This means you may only add credentials using one of your private keys.

The format of ``credentials.json`` includes the half_life of the key, the epoch
signifying when that credential was created and for each key we use to decrypt
the data, a secret that is encrypted with your ssh key, a signature saying your
private key created that secret, and the credentials themselves encrypted with
AES using that secret.

Each ``env.json`` file has a similar format to ``credentials.json`` but it has
type of ``environment`` and includes environment variables that have been captured
by the ``credo capture`` command.

Changelog
---------

0.4.3
    Python3 support

    Some fixes

    Readme improvement

0.4.2
    Trying to fix the launchdaemon to use correct home directory

0.4.1
    Fixed a bug with the chrome extension

    Fixed a bug with generating the shell script

    Added a --config option

0.4.0
    Add more support for credo server.

0.3.3
    Fixed the credo import function

0.3.2
    Some fixes to credo serve

0.3.1
    Doesn't ask for half_life multiple times

    Has a don't rotate option

    One less bug with saving keys on rotate

    Fixed a bug with importing from a boto config

0.3.0
    Added serve and switch to act as a fake metadata service

0.2.8
    Some minor fixes

0.2.7
    Added register_saml function

    And the ability to get credentials from a saml identity provider

0.2.6
    Pinning install_requires dependencies

    Using delfick_error now

0.2.5
    Fixed bug where credo would crash if your ~/.ssh folder had subfolders

    Can now specify --half-life when you do a rotate, exec, inject or exports

    You can now set a ``half_life`` option in ~/.credo/config

0.2.4
    Made it so that --help when used with credo sourceable doesn't return
    exit code 0 because the bash helper would source --help output

0.2.3
    Made pygit2 optional because compiling libgit2 is annoying

0.2.1 and 0.2.2
    Tiny bug fixes I noticed after release

0.2
    Initial version that is open-sourced

The Magic Metadata Server
-------------------------

The magic metadata server provides your local IAM tools with credentials needed
to access your AWS account. It works the same way an ec2 instance is able to
access it's role credentials (over http://169.254.169.254).

There are two parts of the server.

  - The credo shell function that is used as a wrapper to access the `credo`
    tool in your virtualenv.
  - The LaunchDaemon plist which defines how to start the magic metadata
    server.

Setting up the Magic Metadata Server
++++++++++++++++++++++++++++++++++++

The magic metadata server listens at http://169.254.169.254 on your local
machine.

Currently it only supports /latest/meta-data/iam/security-credentials, thus
allowing any amazon sdk to authenticate with Amazon.

Also, it only works with identity provider credentials (so it won't work with
the user credentials you've imported into credo) but that restriction aside,
it does work.

To setup it up on your computer, follow the following instructions:

First, let's choose where you're gonna create a virtualenv for credo.

Let's say ``~/credo_venv``, but you can change that to what you want:

1. ``virtualenv ~/credo_venv``
2. ``source ~/credo_venv/bin/activate``
3. ``pip install credo_manager tornado flask``
4. ``credo create_launch_daemon``

Finally, we shall import accounts:

1. ``credo register_saml``
2. For each account run ``credo import --source saml_provider``

Setting up Helpers
++++++++++++++++++

To help you use the credo, there are some CLI tools and Chrome Extension.

Install the CLI tools:

    ``credo print_shell_function`` and follow instructions.

Install the Chrome Extensions:

    ``credo output_extension --output ~/credo_venv/ext`` and follow instructions.

To quickly switch between environments, you can now run the command ``switch
<environment>``.

Enjoy your new Magic Metadata Server.

Tests
-----

If you're developing it::

    pip install -e .
    pip install -e ".[tests]"

Run the helpful script::

    ./test.sh

Git Integration
---------------

** The Git integration doesn't really work. **

Install the dependencies:

Mac OSX::

    brew install libgit2 gmp

For ubuntu::

    sudo add-apt-repository ppa:dennis/python
    sudo apt-get update
    sudo apt-get install python-crypto python-pygit2

For other systems, see the ``Compiled Python Dependencies`` section below

Compiled Python dependencies
----------------------------

If you don't want to use pre-built packages for pycrypto you could make sure you
don't have that package installed, then install the python development libraries
and the gmp development libraries (gmp is needed for crypto to be faster).

So,

For Debian systems, something like
  sudo apt-get install libpython-dev libgmp-dev

For those with yum
  yum install python-devel gmp-devel

And then do ``pip install credo``.

You can also compile libgit2 yourself if you want::

    # sudo apt-get install cmake gcc
    # or
    # sudo yum install cmake make gcc

    git clone -b master git://github.com/libgit2/libgit2.git
    mkdir libgit2/build
    cd libgit2/build
    cmake ..
    cmake --build .
    sudo cmake --build . --target install

    pip install pygit2

Pygit2 is an optional dependency, and for now, git support is rather weak anyway.
