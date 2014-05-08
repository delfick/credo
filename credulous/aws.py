class FingerprintFiles(object):
	"""Knows about fingerprint files"""
	def __init__(self, location, chosen):
		self.chosen = chosen
		self.location = location

	@property
	def access_key(self):
		return "1"

	@property
	def secret_key(self):
		return "2"

