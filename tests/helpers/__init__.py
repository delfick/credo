"""
    Create a base class that includes all the mixins in the mixins folder
"""
import pkg_resources
import unittest
import os

this_dir = os.path.dirname(__file__)
mixin_dir = os.path.join(this_dir, 'mixins')
credo_dir = os.path.abspath(pkg_resources.resource_filename("credo", ""))

bases = [unittest.TestCase]
for name in os.listdir(mixin_dir):
    if not name or name.startswith("_") or not name.endswith('.py'):
        continue

    # Name convention is <Name>AssertionsMixin
    name = name[:-3]
    mixin = "%sAssertionsMixin" % name.capitalize()
    imported = __import__("mixins.{0}".format(name), globals(), locals(), [mixin], -1)
    bases.append(getattr(imported, mixin))

def credocase_teardown(self):
    """Run any registered teardown function"""
    for tearer in self._teardowns:
        tearer()

def credo_init(self, methodName='runTest'):
    """
    We need to do some trickery with runTest so that it all works.

    Also add any function with the attribute "_credocase_teardown" to self._teardowns
    """
    self._teardowns = []
    for attr in dir(self):
        if getattr(attr, "_credocase_teardown", None):
            self._teardowns.append(getattr(self, attr))

    if methodName == 'runTest':
        methodName = 'empty'
    return unittest.TestCase.__init__(self, methodName)

# Empty function that does nothing
empty_func = lambda self : False

CredoCase = type("CredoCase", tuple(bases)
    , { 'empty' : empty_func
      , '__init__' : credo_init
      , 'tearDown' : credocase_teardown
      , 'teardown' : credocase_teardown
      , 'credo_dir' : credo_dir
      }
    )

