from setuptools import setup, find_packages

setup(
      name = "credo"
    , version = "0.1"
    , packages = ['credo'] + ['credo.%s' % pkg for pkg in find_packages('credo')]
    , include_package_data = True

    , install_requires =
      [ "rainbow_logging_handler"
      , "pycrypto"
      , "paramiko"
      , "keyring"
      , "boto"
      ]

    , extras_require =
      { "tests":
        [ "noseOfYeti>=1.5.0"
        , "nose"
        , "mock"
        ]
      }

    , entry_points =
      { 'console_scripts' :
        [ 'credo = credo.executor:main'
        ]
      }

    # metadata for upload to PyPI
    , url = "http://credo.readthedocs.org"
    , author = "Stephen Moore"
    , author_email = "stephen@delfick.com"
    , description = "Manager for aws credentials"
    , license = "MIT"
    , keywords = "iam amazon credentials"
    )
