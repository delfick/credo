from credo.asker import ask_for_choice, ask_for_public_keys
from credo.errors import UserQuit, BadConfiguration

from pygit2 import Repository as GitRepository
import logging
import json
import os

log = logging.getLogger("credo.versioning")

class NoVersioningDriver(object):
	"""Driver when there is no versioning"""
	def __init__(self, location):
		self.location = location

	def synchronize(self):
		"""No op"""

	@property
	def remote(self):
		"""There is no remote!"""
		return None

class GitDriver(object):
	"""Knows how to use git"""
	def __init__(self, location):
		self.location = location
		self.repo = GitRepository(self.location)

	def synchronize(self):
		"""Stash any changes, fetch, reset, push, unstash"""

	@property
	def remote(self):
		"""Get us back the url of the origin remote"""

class Repository(object):
	"""Understands how to version a directory"""
	def __init__(self, location):
		self.driver = self.determine_driver(location)
		self.location = location

	def determine_driver(self, location):
		"""Get us the driver for our repository"""
		git_folder = os.path.join(location, ".git")
		if os.path.exists(git_folder):
			return GitDriver(location)
		else:
			return NoVersioningDriver(location)

	def synchronize(self):
		"""Ask the driver to synchronize the folder"""
		self.driver.synchronize()

	def add_change(self, message, changed_files):
		"""Ask the driver to add the changed files and commit with the provided message"""

	def get_public_keys(self, ask_anyway=False):
		"""
		Return public keys for this repository as (urls, pems, locations)
		Where locations is a map of {<pem>: <location>} for when we know the location
		"""
		keys_location = os.path.join(self.location, "keys")

		result = {}
		locations = {}

		if os.path.exists(keys_location):
			try:
				with open(keys_location) as fle:
					result = json.load(fle)
			except ValueError as err:
				result = self.fix_keys(keys_location, err)

		if not os.path.exists(keys_location) or ask_anyway:
			urls, pems, locations = ask_for_public_keys(self.driver.remote)

			if "urls" not in result:
				result["urls"] = []
			if "pems" not in result:
				result["pems"] = []
			result["urls"].extend(urls)
			result["pems"].extend(pems)

		urls = result.get("urls")
		pems = result.get("pems")
		if urls or pems:
			try:
				content = json.dumps(result)
			except ValueError as err:
				raise BadConfiguration("Couldn't write out keys json", err=err)

			log.debug("Writing out public keys\tlocation=%s", keys_location)
			with open(keys_location, 'w') as fle:
				fle.write(content)

		return result.get("urls", []), result.get("pems", []), locations

	def fix_keys(self, location, error):
		"""Get user to fix the keys file"""
		info = {"error": error}
		while True:
			quit_choice = "Quit"
			remove_choice = "Remove the file"
			try_again_choice = "I fixed it, Try again"
			choices = [try_again_choice, remove_choice, quit_choice]
			response = ask_for_choice("Couldn't load {0} as a json file ({1})".format(location, info["error"]), choices)

			if response == quit_choice:
				raise UserQuit()

			elif response == remove_choice:
				os.remove(location)
				return {}

			else:
				try:
					return json.load(location)
				except ValueError as err:
					info["error"] = err

