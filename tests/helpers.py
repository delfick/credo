from contextlib import contextmanager
import tempfile
import shutil
import os

@contextmanager
def a_temp_file(body=None):
    filename = None
    try:
        filename = tempfile.NamedTemporaryFile(delete=False).name
        if body:
            with open(filename, 'w') as fle:
                fle.write(body)
        yield filename
    finally:
        if filename and os.path.exists(filename):
            os.remove(filename)

@contextmanager
def a_temp_dir():
    directory = None
    try:
        directory = tempfile.mkdtemp()
        yield directory
    finally:
        if directory and os.path.exists(directory):
            shutil.rmtree(directory)

