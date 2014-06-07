# coding: spec

from credo.explorer import filtered, find_repo_structure, flatten

from tests.helpers import CredoCase

from noseOfYeti.tokeniser.support import noy_sup_setUp
import mock
import json
import os

describe CredoCase, "find_repo_structure":
    it "creates directory_structure and shortened to specified number of levels":
        with self.a_temp_dir() as directory:
            self.touch_files(directory
                , [ "repo1/account1/user1/credentials.json"
                    , "repo1/account1/user1/other.json"
                    , "repo1/yeap"
                    , "repo1/account1/user1/ignored/blah"
                    , "repo1/account2/user1b/credentials.json"
                    , "repo2/account4/user2/things"
                    , "repo3/"
                    , "hmmm"
                    , "repo1/.git/index/"
                    , "repo1/.git/HEAD"
                    , "repo4/meh"
                    , "repo5/account5/"
                    , "repo6/one/two/three/four/five/six"
                    ]
                )

            directory_structure, shortened = find_repo_structure(directory, levels=3)
            expected_shortened = {
                  "repo1": {"account1": {"user1": ["credentials.json", "other.json"]}, "account2": {"user1b": ["credentials.json"]}}
                , "repo2": {"account4": {"user2": ["things"]}}
                , "repo6": {"one": {"two": []}}
                }

            expected_structure = {
                  "/location/": os.path.join(directory, "")
                , "/dirs/": []
                , "/files/": ["hmmm"]
                , "repo1":
                    { "/location/": os.path.join(directory, "repo1", "")
                    , "/dirs/": [".git"]
                    , "/files/": ["yeap"]
                    , "account1":
                        { "/location/": os.path.join(directory, "repo1", "account1", "")
                        , "/dirs/": []
                        , "/files/": []
                        , "user1":
                        { "/location/": os.path.join(directory, "repo1", "account1", "user1", "")
                        , "/files/": ["credentials.json", "other.json"]
                        , "/dirs/": ["ignored"]
                        }
                        }
                    , "account2":
                        { "/location/": os.path.join(directory, "repo1", "account2", "")
                        , "/dirs/": []
                        , "/files/": []
                        , "user1b":
                        { "/location/": os.path.join(directory, "repo1", "account2", "user1b", "")
                        , "/files/": ["credentials.json"]
                        , "/dirs/": []
                        }
                        }
                    }
                , "repo2":
                    { "/location/": os.path.join(directory, "repo2", "")
                    , "/dirs/": []
                    , "/files/": []
                    , "account4":
                    { "/location/": os.path.join(directory, "repo2", "account4", "")
                    , "/dirs/": []
                    , "/files/": []
                        , "user2":
                        { "/location/": os.path.join(directory, "repo2", "account4", "user2", "")
                        , "/files/": ["things"]
                        , "/dirs/": []
                        }
                    }
                    }
                , "repo3":
                    { "/location/": os.path.join(directory, "repo3", "")
                    , "/dirs/": []
                    , "/files/": []
                    }
                , "repo4":
                    { "/location/": os.path.join(directory, "repo4", "")
                    , "/dirs/": []
                    , "/files/": ["meh"]
                    }
                , "repo5":
                    { "/location/": os.path.join(directory, "repo5", "")
                    , "/dirs/": []
                    , "/files/": []
                    , "account5":
                    { "/location/": os.path.join(directory, "repo5", "account5", "")
                    , "/dirs/": []
                    , "/files/": []
                    }
                    }
                , "repo6":
                    { "/location/": os.path.join(directory, "repo6", "")
                    , "/dirs/": []
                    , "/files/": []
                    , "one":
                    { "/location/": os.path.join(directory, "repo6", "one", "")
                    , "/dirs/": []
                    , "/files/": []
                    , "two":
                        { "/location/": os.path.join(directory, "repo6", "one", "two", "")
                        , "/dirs/": []
                        , "/files/": []
                        , "/dirs/": ["three"]
                        }
                    }
                    }
                }

            self.assertJsonDictEqual(directory_structure, expected_structure)
            self.assertJsonDictEqual(shortened, expected_shortened)

    it "creates directory_structure and shortened to specified number of levels with say only one level":
        with self.a_temp_dir() as directory:
            self.touch_files(directory
                , [ "repo1/account1/user1/credentials.json"
                    , "repo1/account1/user1/other.json"
                    , "repo1/yeap"
                    , "repo1/.git/index/"
                    , "repo1/.git/HEAD"
                    , "repo1/account1/user1/ignored/blah"
                    , "repo1/account2/user1b/credentials.json"
                    , "repo2/account4/user2/things"
                    , "repo3/"
                    , "hmmm"
                    , "repo4/meh"
                    , "repo5/account5/"
                    , "repo6/one/two/three/four/five/six"
                    ]
                )

            directory_structure, shortened = find_repo_structure(directory, levels=1)
            expected_shortened = {
                  "repo1": ["yeap"]
                , "repo2": []
                , "repo3": []
                , "repo4": ["meh"]
                , "repo5": []
                , "repo6": []
                }

            expected_structure = {
                  "/location/": os.path.join(directory, "")
                , "/dirs/": []
                , "/files/": ["hmmm"]
                , "repo1":
                    { "/location/": os.path.join(directory, "repo1", "")
                    , "/files/": ["yeap"]
                    , "/dirs/": [".git", "account1", "account2"]
                    }
                , "repo2":
                    { "/location/": os.path.join(directory, "repo2", "")
                    , "/files/": []
                    , "/dirs/": ["account4"]
                    }
                , "repo3":
                    { "/location/": os.path.join(directory, "repo3", "")
                    , "/files/": []
                    , "/dirs/": []
                    }
                , "repo4":
                    { "/location/": os.path.join(directory, "repo4", "")
                    , "/files/": ["meh"]
                    , "/dirs/": []
                    }
                , "repo5":
                    { "/location/": os.path.join(directory, "repo5", "")
                    , "/files/": []
                    , "/dirs/": ["account5"]
                    }
                , "repo6":
                    { "/location/": os.path.join(directory, "repo6", "")
                    , "/files/": []
                    , "/dirs/": ["one"]
                    }
                }

            self.assertJsonDictEqual(directory_structure, expected_structure)
            self.assertJsonDictEqual(shortened, expected_shortened)

describe CredoCase, "filtered":
    it "returns a copy":
        original = {"one": {"two": {"three": ["four"]}}}
        result = filtered(original, looking_for=None, required_files=None)
        self.assertEqual(result, original)
        result["one"] = True
        self.assertEqual(original, {"one": {"two": {"three": ["four"]}}})

    it "returns as is if not looking_for and no required_file":
        original = {"one": {"two": {"three": ["four"]}}}
        result = filtered(original, looking_for=None, required_files=None)
        self.assertEqual(result, original)

    it "returns as is if looking_for only has Nones and no required file":
        original = {"one": {"two": {"three": ["four"]}}}
        result = filtered(original, looking_for=[None, None], required_files=None)
        self.assertEqual(result, original)

    it "filters out things that don't have matching value at a particular level":
        original = {
                "one": {"two": {"three": ["four"]}}
            , "five": {"two": {"six": {"seven": ["eight"]}}}
            , "nine": {"ten": {"three": ["twelve"]}}
            }

        result = filtered(original, looking_for=[None, "two"], required_files=None)
        self.assertEqual(result
            , { "one": {"two": {"three": ["four"]}}
                , "five": {"two": {"six": {"seven": ["eight"]}}}
                }
            )

        result = filtered(original, looking_for=[None, None, "three"], required_files=None)
        self.assertEqual(result
            , { "one": {"two": {"three": ["four"]}}
                , "nine": {"ten": {"three": ["twelve"]}}
                }
            )

        result = filtered(original, looking_for=["one", None, "three"], required_files=None)
        self.assertEqual(result
            , { "one": {"two": {"three": ["four"]}}
                }
            )

    it "filters out things at the last level that don't have the required files":
        original = {
                "one": {"two": {"three": ["four"]}}
            , "five": {"two": {"six": {"seven": ["eight"]}}}
            , "nine": {"ten": {"three": ["four", "twelve"]}}
            }

        result = filtered(original, looking_for=[None, "two", None], required_files=["four"])
        self.assertEqual(result
            , { "one": {"two": {"three": ["four"]}}
                }
            )

        result = filtered(original, looking_for=[None, None, "three"], required_files=["four", "twelve"])
        self.assertEqual(result
            , { "nine": {"ten": {"three": ["four", "twelve"]}}
                }
            )

        result = filtered(original, looking_for=["one", None, "three"], required_files=["five"])
        self.assertEqual(result, {})

    it "filters out things that aren't a list at the last level if required_files":
        original = {
                "one": {"two": {"three": {"four": ["yes"]}}}
            , "nine": {"ten": {"three": {"four": ["twelve"]}}}
            , "nine": {"two": {"three": ["four"]}}
            }

        result = filtered(original, looking_for=[None, "two", None], required_files=["four"])
        self.assertEqual(result
            , { "nine": {"two": {"three": ["four"]}}
                }
            )

        result = filtered(original, looking_for=[None, None, "three"], required_files=["four"])
        self.assertEqual(result
            , { "nine": {"two": {"three": ["four"]}}
                }
            )

describe CredoCase, "flattening":
    it "returns [location, <value>, <value>, ...] for the values in directory_structure that matches the mask":
        with self.a_temp_dir() as directory:
            self.touch_files(directory
                , [ "repo1/account1/user1/credentials.json"
                  , "repo1/account1/user1/other.json"
                  , "repo1/yeap"
                  , "repo1/account1/user1/ignored/blah"
                  , "repo1/account2/user1b/credentials.json"
                  , "repo2/account4/user2/things"
                  , "repo3/"
                  , "hmmm"
                  , "repo1/.git/index/"
                  , "repo1/.git/HEAD"
                  , "repo4/meh"
                  , "repo5/account5/"
                  , "repo6/one/two/three/four/five/six"
                  ]
                )

            directory_structure, _ = find_repo_structure(directory, levels=3)
            mask = {
                  "repo1": {"account1": {"user1": ["credentials.json", "other.json"]}, "account2": {"user1b": ["credentials.json"]}}
                , "repo2": {"account4": {"user2": ["things"]}}
                , "repo6": {"one": {"two": []}}
                }

            flattend = flatten(directory_structure, mask)
            expected_flatten = [
                  [os.path.join(directory, "repo1", "account1", "user1"), "repo1", "account1", "user1"]
                , [os.path.join(directory, "repo1", "account2", "user1b"), "repo1", "account2", "user1b"]
                , [os.path.join(directory, "repo2", "account4", "user2"), "repo2", "account4", "user2"]
                , [os.path.join(directory, "repo6", "one", "two"), "repo6", "one", "two"]
                ]
            self.assertSortedEqual(flattend, expected_flatten)

    it "ignores things that aren't in the directory_structure":
        with self.a_temp_dir() as directory:
            self.touch_files(directory
                , [ "repo1/account1/user1/credentials.json"
                  , "repo1/account1/user1/other.json"
                  , "repo1/account1/user1/ignored/blah"
                  , "repo2/account4/user2/things"
                  ]
                )

            directory_structure, _ = find_repo_structure(directory, levels=3)
            mask = {
                  "repo1": {"account1": {"user1": ["credentials.json", "other.json"]}, "account2": {"user1b": ["credentials.json"]}}
                , "repo2": {"account4": {"user2": ["things"]}}
                , "repo6": {"one": {"two": []}}
                }

            flattend = flatten(directory_structure, mask)
            expected_flatten = [
                  [os.path.join(directory, "repo1", "account1", "user1"), "repo1", "account1", "user1"]
                , [os.path.join(directory, "repo2", "account4", "user2"), "repo2", "account4", "user2"]
                ]
            self.assertSortedEqual(flattend, expected_flatten)

    it "creates things that aren't in the directory_structure if want_new":
        with self.a_temp_dir() as directory:
            self.touch_files(directory
                , [ "repo1/account1/user1/credentials.json"
                  , "repo1/account1/user1/other.json"
                  , "repo1/account1/user1/ignored/blah"
                  , "repo2/account4/user2/things"
                  ]
                )

            directory_structure, _ = find_repo_structure(directory, levels=3)
            mask = {
                  "repo1": {"account1": {"user1": ["credentials.json", "other.json"]}, "account2": {"user1b": ["credentials.json"]}}
                , "repo2": {"account4": {"user2": ["things"]}}
                , "repo6": {"one": {"two": []}}
                }

            flattend = flatten(directory_structure, mask, want_new=True)
            expected_flatten = [
                  [os.path.join(directory, "repo1", "account1", "user1"), "repo1", "account1", "user1"]
                , [os.path.join(directory, "repo1", "account2", "user1b"), "repo1", "account2", "user1b"]
                , [os.path.join(directory, "repo2", "account4", "user2"), "repo2", "account4", "user2"]
                , [os.path.join(directory, "repo6", "one", "two"), "repo6", "one", "two"]
                ]
            self.assertSortedEqual(flattend, expected_flatten)

            location = os.path.join(directory, 'repo6', 'one', 'two')
            self.assertEqual(directory_structure["repo6"]["one"]["two"], {"/location/":location, '/files/':[], '/dirs/':[]})

            location = os.path.join(directory, 'repo1', 'account2', 'user1b')
            self.assertEqual(directory_structure["repo1"]["account2"]["user1b"], {"/location/":location, '/files/':[], '/dirs/':[]})

