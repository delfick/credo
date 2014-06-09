from credo.asker import ask_for_choice, ask_for_public_keys
from credo.errors import UserQuit, BadConfiguration
from credo.versioning import determine_driver

import logging
import json
import os

log = logging.getLogger("credo.versioning")

class Repository(object):
	"""Understands how to version a directory"""
	def __init__(self, name, location, credential_path):
		self.name = name
		self.location = location

		self.driver = determine_driver(location)

	def synchronize(self):
		"""Ask the driver to synchronize the folder"""
		self.driver.synchronize()

	def add_change(self, message, changed_files, **info):
		"""Ask the driver to add the changed files and commit with the provided message"""
		message_suffix = ", ".join("{0}={1}".format(key, val) for key, val in info.items())
		if message_suffix:
			message = "{0} ({1})".format(message, message_suffix)
		self.driver.add_change(message, changed_files)

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
				content = json.dumps(result, indent=4)
			except ValueError as err:
				raise BadConfiguration("Couldn't write out keys json", err=err)

			log.debug("Writing out public keys\tlocation=%s", keys_location)
			with open(keys_location, 'w') as fle:
				fle.write(content)
			self.add_change("Adjusting known public keys", [keys_location], repo=self.name)

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

