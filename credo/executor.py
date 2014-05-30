from credo.actions import do_display, do_exec, do_showavailable, do_import, do_rotate, do_current
from credo.errors import CredoError, NoExecCommand
from credo.asker import secret_sources
from credo.overview import Credo
from credo.crypto import Crypto
from credo import VERSION

from rainbow_logging_handler import RainbowLoggingHandler
import argparse
import logging
import sys
import os

log = logging.getLogger("executor")

def setup_logging(verbose=False, boto_debug=False):
    log = logging.getLogger("")
    handler = RainbowLoggingHandler(sys.stderr)
    handler._column_color['%(asctime)s'] = ('cyan', None, False)
    handler._column_color['%(levelname)-7s'] = ('green', None, False)
    handler._column_color['%(message)s'][logging.INFO] = ('blue', None, False)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)-15s %(message)s"))
    log.addHandler(handler)
    log.setLevel([logging.INFO, logging.DEBUG][verbose])

    if boto_debug:
        logging.getLogger("boto").setLevel(logging.DEBUG)
    else:
        logging.getLogger("boto").setLevel([logging.CRITICAL, logging.ERROR][verbose])

    logging.getLogger("requests").setLevel([logging.CRITICAL, logging.ERROR][verbose])

class CliParser(object):
    def split_argv(self, argv=None):
        """Split the args into (cred_opts, action, action_opts)"""
        if argv is None:
            argv = sys.argv[1:]

        for index, arg in enumerate(argv):
            if arg in self.actions:
                return argv[:index+1], arg, argv[index+1:]

        # Couldn't find a valid action :(
        return argv, None, []

    def parse_args(self, argv=None):
        """
        Get us (credo, kwargs, function)

        Where credo is an overview object of our credo collection

        kwargs is the extra arguments to call the function with

        And function is what we want to call with the kwargs
        The function should have the signature function(credo, **kwargs)
        """
        cred_args, action, action_args = self.split_argv()
        credo = self.make_credo(cred_args, action)
        kwargs, function = self.actions[action](action, action_args)
        return credo, kwargs, function

    @property
    def actions(self):
        return {
              "help": self.parse_help
            , "exec": self.parse_exec
            , "show": self.parse_show
            , "import": self.parse_import
            , "rotate": self.parse_rotate
            , "display": self.parse_display
            , "current": self.parse_current
            }

    def cred_parser(self):
        """Parser for all the common credo options"""
        parser = argparse.ArgumentParser(description="Credo executor")

        parser.add_argument("action"
            , help = "What should credo do today?"
            , choices = self.actions
            )

        parser.add_argument("-a", "--account"
            , help = "The account to use"
            )

        parser.add_argument("-u", "--user"
            , help = "The user to use"
            )

        parser.add_argument("-r", "--repo"
            , help = "The repo to use"
            )

        parser.add_argument("-c", "--creds"
            , help = "Set user and account with user@account syntax"
            )

        parser.add_argument("-v", "--verbose"
            , help = "Show debug log messages"
            , action = "store_true"
            )

        parser.add_argument("--boto-debug"
            , help = "Show debug log messages for boto"
            , action = "store_true"
            )

        return parser

    def args_from_subparser(self, action, parser, argv):
        """Get us args from our parser as a dictionary and make sure our usage statement is nice"""
        cred_usage = self.cred_parser().format_usage().split(":", 1)[1].strip().split("\n")[0]
        subparser_usage = parser.format_usage()
        subparser_usage = subparser_usage[subparser_usage.index(parser.prog)+len(parser.prog):].strip()
        parser.usage = "{0} <|| {1} ||> {2}".format(cred_usage, action, subparser_usage)
        return vars(parser.parse_args(argv))

    def make_credo(self, cred_args, expected_action):
        """Make a Credo object that knows things"""
        cred_parser = self.cred_parser()
        cred_args = cred_parser.parse_args(cred_args)
        setup_logging(verbose=cred_args.verbose, boto_debug=cred_args.boto_debug)

        if cred_args.action != expected_action:
            raise CredoError("Well this is weird, I thought the action was different than it turned out to be", expected=expected_action, parsed=cred_args.action)

        credo = Credo(self.make_crypto())
        credo.find_options(**vars(cred_args))
        return credo

    def make_crypto(self, ssh_key_folders=None):
        """Make the crypto object"""
        if not ssh_key_folders:
            home_ssh = os.path.expanduser("~/.ssh")
            if os.path.exists(home_ssh) and os.access(home_ssh, os.R_OK):
                ssh_key_folders = [home_ssh]

        crypto = Crypto()
        for folder in ssh_key_folders:
            crypto.find_private_keys(folder)
        return crypto

    def parse_help(self, action, argv):
        """Just prints help and quits"""
        # It's late, I'm tired....
        print "Help is not here"
        sys.exit(1)

    def parse_display(self, action, argv):
        """Display doesn't have arguments yet"""
        parser = argparse.ArgumentParser(description="Print out export statements for your aws creds")
        args = self.args_from_subparser(action, parser, argv)
        return args, do_display

    def parse_show(self, action, argv):
        """Parser for showing available credentials"""
        parser = argparse.ArgumentParser(description="Show you the credentials you have")
        parser.add_argument("--all"
            , help = "Force show all available"
            , action = "store_true"
            , dest = "force_show_all"
            )
        parser.add_argument("--no-collapse"
            , help = "Don't collapse output if we only find one"
            , action = "store_false"
            , dest = "collapse_if_one"
            )
        args = self.args_from_subparser(action, parser, argv)
        return args, do_showavailable

    def parse_import(self, action, argv):
        """Import doesn't have any arguments yet"""
        parser = argparse.ArgumentParser(description="Import amazon secrets")
        parser.add_argument("--source"
            , help = "Choose a particular source to get credentials from"
            , choices = secret_sources.keys()
            )
        args = self.args_from_subparser(action, parser, argv)
        return args, do_import

    def parse_rotate(self, action, argv):
        """Rotate doesn't have any arguments yet"""
        parser = argparse.ArgumentParser(description="Rotate amazon secrets")
        args = self.args_from_subparser(action, parser, argv)
        return args, do_rotate

    def parse_current(self, action, argv):
        """Current doesn't have any arguments yet"""
        parser = argparse.ArgumentParser(description="Show what user is currently in your environment")
        args = self.args_from_subparser(action, parser, argv)
        return args, do_current

    def parse_exec(self, action, argv):
        """Exec passes on everything else also doesn't have arguments yet"""
        parser = argparse.ArgumentParser(description="Run the provided command using a sub shell with the aws credentials in it")
        if argv and argv[0] in ("--help", "-h"):
            self.args_from_subparser(action, parser, argv)
            # argparse should already quit before this point
            sys.exit(1)
        else:
            if not argv:
                raise NoExecCommand("argv is empty!")
            return {"command": argv}, do_exec

def main(argv=None):
    __import__("boto")
    useragent = sys.modules["boto.connection"].UserAgent
    sys.modules["boto.connection"].UserAgent = "{0} Credo/{1}".format(useragent, VERSION)

    try:
        credo, kwargs, function = CliParser().parse_args(argv)
        function(credo, **kwargs)
    except CredoError as error:
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

