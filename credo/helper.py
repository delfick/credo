import copy

def record_non_dicts(subject, memo):
	"""Find all the things in subject that are not string or dicts and fill memo with {id(thing): thing}"""
	for key, val in subject.items():
		if not isinstance(val, dict) and not isinstance(val, basestring):
			memo[id(val)] = val

		elif isinstance(val, dict):
			record_non_dicts(val, memo)

def copy_dict_structure(structure):
	"""Copy the structure of a dictionary without modifying any of the contents"""
	memo = {}
	record_non_dicts(structure, memo)
	return copy.deepcopy(structure, memo=memo)
