from setuptools import setup, find_packages
from credo import VERSION

setup(
      name = "credo_manager"
    , version = VERSION
    , packages = ['credo'] + ['credo.%s' % pkg for pkg in find_packages('credo')]
    , include_package_data = True

    , install_requires =
      [ "rainbow_logging_handler==2.2.0"
      , "pycrypto==2.6.1"
      , "paramiko==1.14.0"
      , "requests==2.2.1"
      , "keyring==3.5"
      , "boto>=2.32.1"
      , "delfick_error==1.6"
      , "pytz"
      , "six"
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
    , license = "MIT"
    , keywords = "iam amazon credentials"
    )
