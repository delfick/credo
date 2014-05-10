from setuptools import setup, find_packages

setup(
      name = "credulous"
    , version = "0.1"
    , packages = ['credulous'] + ['credulous.%s' % pkg for pkg in find_packages('credulous')]
    , include_package_data = True

    , install_requires =
      [ "rainbow_logging_handler"
      , "pycrypto"
      , "paramiko"
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
        [ 'credulous = credulous.executor:main'
        ]
      }

    # metadata for upload to PyPI
    , url = "http://credulous.readthedocs.org"
    , author = "Stephen Moore"
    , author_email = "stephen@delfick.com"
    , description = "Manager for aws credentials"
    , license = "MIT"
    , keywords = "iam amazon credentials"
    )
