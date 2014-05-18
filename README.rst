Credo
=====

The python version of Credo

Credo is a credential management program for amazon credentials written
in golang. It can be found at https://github.com/realestate-com-au/credo

Usage
-----

Something like::

    credo exec bash -c 'echo $AWS_ACCESS_KEY_ID'

Installation
------------

Use pip!::

    pip install credo

Or if you're developing it::

    pip install -e .
    pip install -e ".[tests]"

Tests
-----

Run the helpful script::

    ./test.sh

