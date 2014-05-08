from credulous.errors import CredulousError

from rainbow_logging_handler import RainbowLoggingHandler
import argparse
import logging
import sys

log = logging.getLogger("executor")

def setup_logging():
    log = logging.getLogger("")
    handler = RainbowLoggingHandler(sys.stderr)
    handler._column_color['%(asctime)s'] = ('cyan', None, False)
    handler._column_color['%(levelname)-7s'] = ('green', None, False)
    handler._column_color['%(message)s'][logging.INFO] = ('blue', None, False)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)-15s %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)

def get_parser():
    parser = argparse.ArgumentParser(description="Credulous executor")
    return parser

def main(argv=None):
    parser = get_parser()
    args = parser.parse_args(argv)
    setup_logging()

    try:
        print "Do things here", args
    except CredulousError as error:
        print ""
        print "!" * 80
        print "Something went wrong! -- {0}".format(error.__class__.__name__)
        print "\t{0}".format(error)
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass

