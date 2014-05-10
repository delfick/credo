from credulous.errors import NoConfigFile, BadConfigFile
from credulous.credentials import Credentials

import json
import sys
import os

class Unspecified(object):
    """Telling the difference between None and just not specified"""

class Credulous(object):
    """Incredible credulous knows all"""

    @property
    def current_creds(self):
        """Return our current creds"""
        return self.chosen.access_key, self.chosen.secret_key

    @property
    def chosen(self):
        """Return our chosen creds"""
        if not hasattr(self, "_chosen"):
            self._chosen = self.find_credentials()
            self.set_options(repo=self._chosen.repo, account=self._chosen.account, user=self._chosen.user)
        return self._chosen

    def find_credentials(self, directory_structure=None, chain=None, chosen=None):
        """
        Traverse our directory structure, asking as necessary

        and return the credentials object we find
        """
        if directory_structure is None:
            _, directory_structure = self.explore()

        if chain is None:
            chain = [("repo", "Repository"), ("account", "Account"), ("user", "User")]

        if chosen is None:
            chosen = []

        nxt, category = chain.pop(0)
        if len(directory_structure) is 1:
            val = directory_structure.keys()[0]
        else:
            val = self.ask_for_choice(category, sorted(directory_structure.keys()))

        chosen.append((nxt, val))
        if not chain:
            return directory_structure[val]
        else:
            return self.find_credentials(directory_structure[val], list(chain), list(chosen))

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

    def explore(self):
        """Explore our root directory"""
        if not os.path.exists(self.root_dir):
            return {}

        return self.find_repo_structure(self.root_dir)

    def find_repo_structure(self, root_dir, chain=None, collection=None, sofar=None, complete=None):
        """
        Recursively explore a directory structure and put it in a dictionary

        So say we had a directory of

            <root>/

                github.com:blah/
                    prod/
                        user1/
                            credentials.json

                bitbucket.com:blah
                    dev/
                        user1/

        And we did

            collection, complete = find_repo_structure(<root>)

        collection would become

            { "repos":
              { "github.com:blah" :
                { "accounts":
                  { "prod":
                    { "users":
                      { "user1": { "/files/": ["credentials.json"], "/credentials/": <Credentials object over crdentials.json>, "/location/": <location> }
                      , "/files/": []
                      , "/location/": "#{<root>}/repos/github.com:blah/prod/user1"
                      }
                    , "/files/": []
                    , "/location/": "#{<root>}/repos/github.com:blah/prod"
                    }
                  }
                , "/files/": []
                , "/location/": "#{<root>}/repos/github.com:blah/prod"
                }
              , "bitbucket.com:blah":
                { "accounts":
                  { "dev":
                    { "users":
                      { "user1": {"/files/": [], "/location/": <location> }
                      , "/files/" []
                      , "/location/": "#{<root>}/repos/bitbucket.com:blah/dev/user1"
                      }
                    , "/files/": []
                    , "/location/": "#{<root>}/repos/bitbucket.com:blah/dev"
                    }
                  }
                , "/files/": []
                , "/location/": "#{<root>}/repos/bitbucket.com:blah"
                }
              }
            , "/files/": []
            , "/location/": "#{<root>}/repos"
            }

        and complete would become

            {"github.com:blah": {"prod": {}}}
        """
        if chain is None:
            chain = ["repos", "accounts", "users"]

        if sofar is None:
            sofar = []

        if complete is None:
            complete = {}

        if collection is None:
            collection = {}

        dirs = []
        files = []
        basenames = []
        for filename in os.listdir(root_dir):
            location = os.path.join(root_dir, filename)
            if os.path.isfile(location):
                files.append(location)
                basenames.append(filename)
            else:
                dirs.append((filename, location))

        collection["/files/"] = files
        collection["/location/"] = root_dir

        if not chain:
            required_file = "credentials.json"
            if required_file in basenames:
                credential = Credentials(os.path.join(root_dir, required_file), repo=sofar[0], account=sofar[1], user=sofar[2])
                c = complete
                for part in sofar[:-1]:
                    if part not in c:
                        c[part] = {}
                    c = c[part]
                c[sofar[-1]] = credential
                collection["/credentials/"] = credential
            return

        # Pop the chain!
        category = chain.pop(0)
        collection[category] = {}

        for filename, location in dirs:
            result = self.find_repo_structure(location, list(chain), sofar=list(sofar) + [filename], complete=complete)
            if result:
                result = result[0]
            collection[category][filename] = result

        return collection, complete

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

