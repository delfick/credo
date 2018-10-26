from setuptools import setup, find_packages
from credo import VERSION

setup(
      name = "credo_manager"
    , version = VERSION
    , packages = ['credo'] + ['credo.%s' % pkg for pkg in find_packages('credo')]
    , include_package_data = True

    , install_requires =
      [ "rainbow_logging_handler==2.2.2"
      , "pycryptodome==3.6.6"
      , "paramiko==2.4.2"
      , "requests==2.19.1"
      , "keyring==13.2.1"
      , "boto==2.49.0"
      , "delfick_error==1.7.8"
      , "pytz"
      ]

    , extras_require =
      { "tests":
        [ "noseOfYeti>=1.5.0"
        , "nose"
        , "mock"
        ]

      , "git":
        [ "pygit2"
        ]
      }

    , entry_points =
      { 'console_scripts' :
        [ 'credo = credo.executor:main'
        ]
      }

    # metadata for upload to PyPI
    , url = "https://github.com/delfick/credo"
    , author = "Stephen Moore"
    , author_email = "stephen@delfick.com"
    , description = "Manager for aws credentials"
    , long_description = open("README.rst").read()
    , license = "MIT"
    , keywords = "iam amazon credentials"
    )
