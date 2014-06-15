from credo.errors import NoConfigFile, BadConfigFile, BadConfiguration, CredoProgrammerError, CredoError, RepoError
from credo.asker import ask_for_choice, ask_for_choice_or_new, ask_for_ssh_key_folders
from credo.structure.credential_path import CredentialPath
from credo.crypto import Crypto
from credo import explorer

import logging
import json
import os

log = logging.getLogger("credo.overview")

class Unspecified(object):
    """Telling the difference between None and just not specified"""

class ConfigFileProperty(object):
    """A property that complains if it hasn't been set yet because setup must be called on Credo"""
    def __init__(self, name):
        self.name = "_{0}".format(name)

    def __get__(self, obj, type=None):
        if not hasattr(obj, self.name):
            raise CredoProgrammerError("Credo object needs to have setup() called before being used")
        return getattr(obj, self.name)

    def __set__(self, obj, val):
        setattr(obj, self.name, val)

class Credo(object):
    """Incredible credo knows all"""

    ########################
    ###   USAGE
    ########################

    @property
    def chosen(self):
        """Return our chosen creds"""
        if not hasattr(self, "_chosen"):
            self._chosen = self.make_chosen(rotate=True)
        return self._chosen

    def setup(self, config_file=Unspecified, root_dir=Unspecified, ssh_key_folders=Unspecified, **kwargs):
        """Setup the credo!"""
        if config_file is Unspecified:
            config_file = self.find_config_file(config_file)

        if config_file:
            if not os.path.exists(config_file):
                raise NoConfigFile("Specified location is empty", location=config_file)
            if not os.access(config_file, os.R_OK):
                raise BadConfigFile("Config file isn't readable", location=config_file)

            self.read_from_config(config_file)

        # Override the root dir and ssh_key_folders if supplied
        for key, val in (("root_dir", root_dir), ("ssh_key_folders", ssh_key_folders)):
            if val is not Unspecified:
                setattr(self, key, val)
            elif not hasattr(self, key):
                setattr(self, key, None)

        try:
            if self.root_dir and not os.path.exists(self.root_dir):
                os.makedirs(self.root_dir)
        except OSError as error:
            raise BadConfiguration("root_dir didn't exist and couldn't be made", root_dir=root_dir, error=error)

        self.set_options(**kwargs)
        self.validate_options()

    ########################
    ###   ATTRIBUTES SET BY OPTIONS
    ########################

    root_dir = ConfigFileProperty("root_dir")
    ssh_key_folders = ConfigFileProperty("ssh_key_folders")
    options_from_config = ["root_dir", "ssh_key_folders"]

    def validate_options(self):
        """Make sure our options make sense"""
        errors = []
        if not self.root_dir:
            errors.append(BadConfiguration("Couldn't work out the root directory for your credentials..."))

        if self.ssh_key_folders:
            if not isinstance(self.ssh_key_folders, list):
                errors.append(BadConfiguration("ssh_key_folders is not a list", value_type=type(self.ssh_key_folders)))
            else:
                for folder in self.ssh_key_folders:
                    if not os.path.exists(folder):
                        errors.append(BadConfiguration("Given an ssh_key_folder that doesn't exist", folder=folder))

        if errors:
            raise BadConfiguration(errors=errors)

    ########################
    ###   CRYPTO
    ########################

    @property
    def crypto(self):
        """Memoize a crypto object"""
        if not getattr(self, "_crypto", None):
            self._crypto = self.make_crypto(self.ssh_key_folders)
        return self._crypto

    def make_crypto(self, ssh_key_folders=None):
        """Make the crypto object"""
        if not ssh_key_folders:
            home_ssh = os.path.expanduser("~/.ssh")
            if os.path.exists(home_ssh) and os.access(home_ssh, os.R_OK):
                ssh_key_folders = [home_ssh]
            else:
                ssh_key_folders = []

        crypto = Crypto()
        for folder in ssh_key_folders:
            crypto.find_keys(folder)

        # Keep asking for folders until we can sign
        while not crypto.has_private_keys():
            more_ssh_key_folders = ask_for_ssh_key_folders(already_have=crypto.ssh_key_folders)
            for folder in set(ssh_key_folders + crypto.ssh_key_folders + more_ssh_key_folders):
                crypto.find_keys(folder)

        return crypto

    ########################
    ###   CHOSEN CREDENTIALS
    ########################

    def make_chosen(self, rotate=True, invalidate_creds=False):
        """Make the chosen credentials from our repository"""
        structure, chains = self.find_credentials(asker=ask_for_choice)
        chosen = list(self.credentials_from(structure, chains, complain_if_missing=True))[0]
        chosen.credential_path.repository.pub_key_syncer.sync()

        if invalidate_creds:
            chosen.invalidate_creds()

        self.set_options(repo=chosen.credential_path.repository.name, account=chosen.credential_path.account.name, user=chosen.credential_path.user.name)

        if rotate:
            if chosen.keys.needs_rotation():
                changed = chosen.credential_path.repository.synchronize(override=True)
                if changed:
                    chosen.load()
                    chosen.credential_path.repository.pub_key_syncer.sync()

            chosen.save()
        return chosen

    def find_credentials(self, asker=None, missing_is_bad=False, want_new=False, no_mask=False):
        """
        Traverse our directory structure, asking as necessary

        and return the credentials object we find
        """
        directory_structure, shortened = explorer.find_repo_structure(self.root_dir, levels=3)
        if no_mask:
            mask = shortened
        else:
            mask = explorer.filtered(shortened, [self.repo, self.account, self.user], required_files=["credentials.json"])

        forced_vals = []
        if want_new:
            forced_vals = [self.repo, self.account, self.user]

        if asker:
            explorer.narrow(mask, ["Repository", "Account", "User"], asker, want_new=want_new, forced_vals=forced_vals)

        return directory_structure, explorer.flatten(directory_structure, mask, want_new=want_new)

    def credentials_from(self, directory_structure, chains, complain_if_missing=False):
        """Yield the credentials from the [location, <repo>, <account>, <user>] chains that are provided"""
        if not chains and complain_if_missing:
            raise CredoError("Didn't find any credentials!")

        for chain in chains:
            location, repo, account, user = chain
            credentials_location = os.path.join(location, "credentials.json")

            if not os.path.exists(credentials_location) and complain_if_missing:
                raise CredoError("Trying to find credentials that don't exist!", repo=repo, account=account, user=user)

            credential_path = CredentialPath(self.crypto)
            credential_path.fill_out(directory_structure, repo, account, user)
            credentials = credential_path.credentials
            credentials.load()
            yield credentials

    def find_one_repository(self, want_new=True):
        """Find one repository and return it's name and location"""
        _, shortened = explorer.find_repo_structure(self.root_dir, levels=1)
        mask = explorer.filtered(shortened, [self.repo])
        asker = ask_for_choice_or_new
        if not want_new:
            asker = ask_for_choice
        explorer.narrow(mask, ["Repository"], asker, want_new=want_new, forced_vals=[self.repo])
        if not mask:
            raise RepoError("Couldn't find a repository to work with.... try importing some keys....")

        repo_name = mask.keys()[0]
        location = os.path.join(self.root_dir, repo_name)
        return repo_name, location

    def find_credential_path_part(self, all_accounts=False, all_users=False, find_user=False):
        """Find a repository, account or user"""
        directory_structure, shortened = explorer.find_repo_structure(self.root_dir, levels=3)
        mask = explorer.filtered(shortened, [self.repo, self.account, self.user])
        asker = ask_for_choice

        user_title = explorer.Stop if all_users else "User"
        account_title = explorer.Stop if all_accounts else "Account"
        want_any_after = 1
        if find_user:
            want_any_after = None
        explorer.narrow(mask, ["Repository", account_title, user_title], asker, want_any_after=want_any_after)
        if not mask:
            raise CredoError("Couldn't find anything to work with")

        repo = mask.keys()[0]
        user = None
        account = None
        if mask[repo]:
            account = mask[repo].keys()[0]
            if mask[repo][account]:
                user = mask[repo][account].keys()[0]

        credential_path = CredentialPath(self.crypto)
        credential_path.fill_out(directory_structure, repo, account, user)

        if credential_path.user:
            return credential_path.user
        elif credential_path.account:
            return credential_path.account
        else:
            return credential_path.repository

    ########################
    ###   CONFIGURATION
    ########################

    def set_options(self, **kwargs):
        """Set specific options"""
        repo = kwargs.get("repo")
        user = kwargs.get("user")
        account = kwargs.get("account")

        if account and "@" in account:
            if account.count("@") > 1:
                raise BadConfiguration("Account may only have one @ in it", account=account)
            account, repo = account.split("@")

        if user and "@" in user:
            if user.count("@") > 2:
                raise BadConfiguration("User may only have a max of two @ in it", user=user)
            elif user.count("@") == 2:
                user, account, repo = user.split("@")
            else:
                user, account = user.split("@")

        for attribute, val in (("user", user), ("account", account), ("repo", repo)):
            if getattr(self, attribute, None) is None:
                if val:
                    val = val.strip()
                setattr(self, attribute, val)

    def find_config_file(self, config_file=Unspecified):
        """Find a config file, use the one given if specified"""
        if config_file is not Unspecified:
            return config_file

        credo_home = os.path.expanduser("~/.credo")
        home_config = os.path.join(credo_home, "config.json")
        if os.path.exists(home_config) and os.stat(home_config).st_size > 0:
            return home_config

        if not os.path.exists(credo_home):
            os.makedirs(credo_home)
        json.dump({"root_dir": os.path.expanduser("~/.credo/repos")}, open(home_config, "w"))
        return home_config

    def read_from_config(self, config_file):
        """Call find_options using options from the config file"""
        options = json.load(open(config_file))
        for option in self.options_from_config:
            if option in options:
                setattr(self, option, options[option])

