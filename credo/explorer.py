from credo.credentials import Credentials

import copy
import os

class Explorer(object):
    """Knows how to read a credo repo structure"""
    def __init__(self, root_dir):
        self.root_dir = root_dir

    @property
    def directory_structure(self):
        return self.explored[0]

    @property
    def completed(self):
        return self.explored[1]

    @property
    def explored(self):
        if not hasattr(self, "_explored"):
            self._explored = self.explore()
        return self._explored

    def explore(self):
        """Explore our root directory"""
        if not os.path.exists(self.root_dir):
            return {"/location/": self.root_dir, "/files/": []}, {}
        return self.find_repo_structure(self.root_dir)

    def filtered(self, repo=None, account=None, user=None):
        result = copy.deepcopy(self.completed)
        fltr = [(key, val) for key, val in ("repo", repo), ("account", account), ("user", user), if val]

        if fltr:
            if user:
                for the_repo, accounts in result.items():
                    for the_account, users in accounts.items():
                        for the_user in users.keys():
                            if the_user != user:
                                del users[the_user]

            for the_repo, accounts in result.items():
                for the_account, users in accounts.items():
                    if account and the_account != account:
                        del accounts[the_account]
                    if not users and the_account in accounts:
                        del accounts[the_account]

            for the_repo, accounts in result.items():
                if repo and the_repo != repo:
                    del result[the_repo]
                if not accounts and the_repo in result:
                    del result[the_repo]

        return result, fltr

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
            , "/location/": "#{<root>}"
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

