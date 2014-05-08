from credulous.errors import NoConfigFile, BadConfigFile, NotEnoughInfo, CredulousError, BadConfig
from credulous.aws import FingerprintFiles

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
		destination, chosen = self.traverse_and_ask([("repos", "repo"), ("accounts", "account_id"), ("users", "iam_user")], self.explore())
		return FingerprintFiles(destination, chosen)

	def traverse_and_ask(self, chain, directory_structure, chosen=[]):
		"""
		Traverse our directory structure, asking as necessary

		Return (location, chosen)

		Where location is the path of the final level

		and chosen is a dictionary of all our choices
		"""
		if not chain:
			raise CredulousError("Well, we failed at making this recursive function :(")

		category, nxt = chain[0]
		for_looking_at = directory_structure[category]
		if not for_looking_at:
			raise NotEnoughInfo("Directory is empty, still looking for things", chain=chain, chosen=chosen)

		chain.pop(0)
		result = None
		if not getattr(self, nxt, Unspecified) in (Unspecified, "", None):
			val = getattr(self, nxt)
		else:
			keys = for_looking_at.keys()
			if len(keys) is 1:
				val = keys[0]
			else:
				val = self.ask_for_choice(nxt, keys)

			setattr(self, nxt, val)

		if val not in for_looking_at:
			raise BadConfig("Wanted a {0} that doesn't exist".format(nxt), wanted=val)

		result = for_looking_at[val]
		chosen.append((nxt, val))
		if not chain:
			return result["/location/"], dict(chosen)
		else:
			return self.traverse_and_ask(list(chain), result, list(chosen))

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

	def give_options(self, config_file=Unspecified, root_dir=Unspecified, **kwargs):
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

		for attribute in ("iam_user", "account_id", "repo"):
			if not hasattr(self, attribute) and attribute in kwargs:
				setattr(self, attribute, kwargs[attribute])

	def explore(self):
		"""Explore our root directory"""
		if not os.path.exists(self.root_dir):
			return {}

		everything = self.find_repo_structure(self.root_dir, ["repos", "accounts", "users", "fingerprints"])
		return everything

	def find_repo_structure(self, root_dir, chain, collection=None):
		"""
		Recursively explore a directory structure and put it in a dictionary

		So say we had a directory of

			<root>/

				github.com:blah/
					fingerprint1.blah

				bitbucket.com:blah
					fingerprint2.blah

		And we did

			collection = find_repo_structure(<root>, ["repos", "fingerprints"])

		collection would become

			{ "repos":
			  { "github.com:blah" : {"/files/": ["fingerprint1.blah"], "/location/": "#{<root>}/repos/github.com:blah"}
			  , "bitbucket.com:blah": {"/files/": ["fingerprint2.blah"], "/location/": "#{<root>}/repos/bitbucket.com:blah"}
			  }
			, "/files/": []
			, "/location/": "#{<root>}/repos"
			}
		"""
		if collection is None:
			collection = {}

		dirs = []
		files = []
		for filename in os.listdir(root_dir):
			location = os.path.join(root_dir, filename)
			if os.path.isfile(location):
				files.append(location)
			else:
				dirs.append((filename, location))

		collection["/files/"] = files
		collection["/location/"] = root_dir

		if not chain:
			return

		# Pop the chain!
		category = chain.pop(0)
		collection[category] = {}

		for filename, location in dirs:
			collection[category][filename] = self.find_repo_structure(location, list(chain))

		return collection

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
		"""Call give_options using options from the config file"""
		# What's an error handling?
		options = json.load(open(config_file))
		options["config_file"] = None
		self.give_options(**options)

