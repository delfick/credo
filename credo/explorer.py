from credo.helper import copy_dict_structure

from fnmatch import fnmatch
import os

def filtered(original, looking_for=None, required_files=None):
    """
    Filter out unwanted entries from a nested dictionary structure

    Where looking_for is a list of strings specifying value at that level.

    So if looking_for is ["repo", None, "user1"] then we will return only those
    that have "repo" at level0 and "user1" at level2 and those required_files at that level
    """
    result = copy_dict_structure(original)
    if not looking_for or (not required_files and not any(looking_for)):
        return result

    def delete_not(original, last_level, wanted, only_if=None):
        """
        Delete from the bottom if the last level is not our wanted level

        if only_if is specified then delete if only_if returns False

        Delete up if what we delete has no siblings
        """
        thing = original
        if isinstance(thing, dict):
            if last_level > 0:
                for key, val in thing.items():
                    delete_not(thing[key], last_level-1, wanted, only_if=only_if)
                    if not val or (last_level-1 > 0 and not isinstance(val, dict)):
                        del thing[key]
            else:
                for key, val in thing.items():
                    if wanted and not fnmatch(key, wanted):
                        del thing[key]
                    elif only_if and not only_if(val):
                        del thing[key]

    def has_required_files(val):
        """
        Say if the required files are here.
        True if we have no required Files
        False if the value isn't a list
        False if all the required files aren't in the value
        True if the val is a list and all the required files are in it
        """
        if not required_files:
            return True
        if not isinstance(val, list):
            return False
        return all(required_file in val for required_file in required_files)

    last_level = len(looking_for) - 1
    wanted = looking_for[last_level]
    if wanted or required_files:
        delete_not(result, last_level, wanted, only_if=has_required_files)

    while last_level > -1:
        if last_level > -1:
            wanted = looking_for[last_level]
            if wanted:
                delete_not(result, last_level, wanted)
            last_level -= 1

    return result

def find_repo_structure(root_dir, collection=None, sofar=None, shortened=None, levels=3):
    """
    Recursively explore a directory structure and put it in a dictionary to the number of levels specified

    So say we had a directory of

        <root>/

            github.com:blah/
                prod/
                    .git/
                        HEAD
                        index/
                    user1/
                        credentials.json

            bitbucket.com:blah
                dev/
                    user1/
                        ignored/
                            ignored2/

    And we did

        collection, shortened = find_repo_structure(<root>)

    collection would become

        { "github.com:blah" :
            { "prod":
            { "user1": { "/files/": ["credentials.json"], "/dirs/": [], "/location/": <location> }
                , "/dirs/": []
            , "/files/": []
            , "/location/": "#{<root>}/github.com:blah/prod/"
            }
            , "/dirs/": [".git"]
            , "/files/": []
            , "/location/": "#{<root>}/github.com:blah/"
            }

        , "bitbucket.com:blah":
            { "dev":
                { "user1": {"/files/": [], "/dirs/": ["ignored"], "/location/": <location> }
                , "/dirs/": []
                , "/files/" []
                , "/location/": "#{<root>}/bitbucket.com:blah/dev/"
                }
            , "/dirs/": []
            , "/files/": []
            , "/location/": "#{<root>}/bitbucket.com:blah/"
            }
        , "/files/": []
        , "/location/": "#{<root>}"
        }

    and shortened would become

        {"github.com:blah": {"prod": {"user1": ["credentials.json"]}}}
    """
    dirs = []
    basenames = []
    extra_dirs = []

    sofar = [] if sofar is None else sofar
    shortened = {} if shortened is None else shortened
    collection = {} if collection is None else collection

    for filename in os.listdir(root_dir):
        location = os.path.join(root_dir, filename)
        if os.path.isfile(location):
            basenames.append(filename)
        else:
            if filename.startswith("."):
                extra_dirs.append(filename)
            else:
                dirs.append((filename, location))

    collection["/dirs/"] = extra_dirs
    collection["/files/"] = basenames
    collection["/location/"] = root_dir
    if not collection["/location/"].endswith('/'):
        collection["/location/"] = "{0}/".format(collection["/location/"])

    if levels == 0:
        s = shortened
        collection["/dirs/"] = extra_dirs + [dr for dr, _ in dirs]
        for part in sofar[:-1]:
            if part not in s:
                s[part] = {}
            s = s[part]
        s[sofar[-1]] = basenames
    else:
        for filename, location in dirs:
            nxt_collection = {}
            collection[filename] = nxt_collection
            find_repo_structure(location, collection=nxt_collection, sofar=list(sofar) + [filename], shortened=shortened, levels=levels-1)

    return collection, shortened

class Stop(object):
    """Used to stop searching in narrow"""

def narrow(structure, chain, asker, want_new=None, want_any_after=None, forced_vals=None, level=0):
    """Narrow down our mask to a single result"""
    if not chain:
        return
    else:
        nxt = chain.pop(0)
        if nxt is Stop:
            chosen = nxt
        else:
            chosen = None

        if forced_vals:
            chosen = forced_vals.pop(0)

        if not chosen:
            if want_any_after is not None and level >= want_any_after:
                choices = sorted(structure.keys())
                all_choice = "All {0}".format(nxt)
                chosen = asker(nxt, choices + [all_choice])
                if chosen == all_choice:
                    chosen = Stop
            else:
                if len(structure.keys()) > 1 or want_new:
                    chosen = asker(nxt, sorted(structure.keys()))
                elif structure:
                    chosen = structure.keys()[0]

        for key in structure.keys():
            if key != chosen:
                del structure[key]

        if not structure and want_new:
            structure[chosen] = {} if chain else []

        if structure:
            narrow(structure.values()[0], chain, asker, want_new=want_new, want_any_after=want_any_after, forced_vals=forced_vals, level=level+1)

def flatten(directory_structure, mask, want_new=False):
    """
    Given a collection and shortened like what find_repo_structure gives,
    return a list of lists of [final_location, <val>, <val>, ...]

    So given a directory_structure of:

        { "/location/": <root>
        , "/files/": <root_files>
        , "/dirs/": <root_extra_dirs>
        , "repo1":
            { "/location/" and "/files/" and "/dirs/"
            , "account1":
              { "/location/" and "/files/" and "/dirs/"
              , "user1":
                { <you get the idea>
                }
              , <other users>
              }
            , <other accounts>
            }
        , <other_repos>
        }

    And a mask of {"repo1": {"account1": {"user1": [], <other_user>: []}}}

    Return

        [ [<user1_root>, "repo1", "account1", "user1"]
        , [<other_user_root>, "repo1", "account1", <other_user>]
        ]

    """
    def fill_out(structure, mask, collected=None):
        """Recursively fill out the collected from structure"""
        new_collected = []

        for nxt, remaining_mask in mask.items():
            if nxt not in structure and want_new:
                location = os.path.join(structure['/location/'], nxt)
                structure[nxt] = {'/location/': location, '/files/': [], '/dirs/': []}

            if nxt in structure:
                if collected is None:
                    collected = [[structure["/location/"]]]
                extended = [collection + [nxt] for collection in collected]
                if isinstance(remaining_mask, dict):
                    new_collected.extend(fill_out(structure[nxt], remaining_mask, extended))
                else:
                    new_collected.extend(extended)

        return new_collected

    collected = fill_out(directory_structure, mask)
    return [[os.path.join(*chain)] + chain[1:] for chain in collected]

