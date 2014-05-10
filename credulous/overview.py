from credulous.errors import NoConfigFile, BadConfigFile
from credulous.explorer import Explorer

import json
import sys
import os

class Unspecified(object):
    """Telling the difference between None and just not specified"""

class Credulous(object):
    """Incredible credulous knows all"""

    @property
    def chosen(self):
        """Return our chosen creds"""
        if not hasattr(self, "_chosen"):
            self._chosen = self.find_credentials()
            self.set_options(repo=self._chosen.repo, account=self._chosen.account, user=self._chosen.user)
        return self._chosen

    def make_explorer(self):
        """Make us an explorer"""
        return Explorer(self.root_dir)

    def find_credentials(self, completed=None, chain=None, chosen=None):
        """
        Traverse our directory structure, asking as necessary

        and return the credentials object we find
        """
        if completed is None:
            completed = self.make_explorer().completed

        if chain is None:
            chain = [("repo", "Repository"), ("account", "Account"), ("user", "User")]

        if chosen is None:
            chosen = []

        nxt, category = chain.pop(0)
        if len(completed) is 1:
            val = completed.keys()[0]
        else:
            val = self.ask_for_choice(category, sorted(completed.keys()))

        chosen.append((nxt, val))
        if not chain:
            return completed[val]
        else:
            return self.find_credentials(completed[val], list(chain), list(chosen))

    def ask_for_choice(self, needed, choices):
        """Ask for a value from some choices"""
        mapped = dict(enumerate(sorted(choices)))
        no_value = True
        while no_value:
            print >> sys.stderr, "Please choose a value from the following"
            for num, val in mapped.items():
                print >> sys.stderr, "{0}) {1}".format(num, val)

            response = raw_input(": ")

            if response is None or not response.isdigit() or int(response) not in mapped:
                print >> sys.stderr, "Please choose a valid response ({0} is not valid)".format(response)
            else:
                no_value = False
                return mapped[int(response)]

    def find_options(self, config_file=Unspecified, root_dir=Unspecified, **kwargs):
        """Setup the credulous!"""
        if config_file is Unspecified:
            config_file = self.find_config_file(config_file)

        if config_file:
            if not os.path.exists(config_file):
                raise NoConfigFile("Specified location is empty", location=config_file)
            if not os.access(config_file, os.R_OK):
                raise BadConfigFile("Config file isn't readable", location=config_file)

            self.read_from_config(config_file)

        # Override the root dir if supplied
        if root_dir is not Unspecified:
            self.root_dir = root_dir

        self.set_options(**kwargs)

    def set_options(self, **kwargs):
        """Set specific options"""
        for attribute in ("user", "account", "repo"):
            if not getattr(self, attribute, None) and attribute in kwargs:
                setattr(self, attribute, kwargs[attribute])

    def find_config_file(self, config_file=Unspecified):
        """Find a config file, use the one given if specified"""
        if config_file is not Unspecified:
            return config_file

        credulous_home = os.path.expanduser("~/.credulous")
        home_config = os.path.join(credulous_home, "config.json")
        if os.path.exists(home_config) and os.stat(home_config).st_size > 0:
            return home_config

        if not os.path.exists(credulous_home):
            os.makedirs(credulous_home)
        json.dump({"root_dir": os.path.expanduser("~/.credulous/repos")}, open(home_config, "w"))
        return home_config

    def read_from_config(self, config_file):
        """Call find_options using options from the config file"""
        # What's an error handling?
        options = json.load(open(config_file))
        options["config_file"] = None
        self.find_options(**options)

