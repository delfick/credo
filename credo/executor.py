from credo.actions import do_display, do_exec, do_showavailable, do_import, do_rotate, do_current, do_remote, do_synchronize
from credo.errors import CredoError, NoExecCommand
from credo.asker import secret_sources
from credo.overview import Credo
from credo import VERSION

from rainbow_logging_handler import RainbowLoggingHandler
import argparse
import logging
import sys

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
            , "remote": self.parse_remote
            , "import": self.parse_import
            , "rotate": self.parser_for_no_args("Rotate amazon secrets", do_rotate)
            , "inject": self.parser_for_no_args("Print out export statements for your aws creds", do_display)
            , "display": self.parser_for_no_args("Print out export statements for your aws creds", do_display)
            , "current": self.parser_for_no_args("Show what user is currently in your environment", do_current)
            , "synchronize": self.parser_for_no_args("Synchronise with the remote for some repository", do_synchronize)
            }

    def cred_parser(self):
        """Parser for all the common credo options"""
        parser = argparse.ArgumentParser(description="Credo executor")

        parser.add_argument("action"
            , help = "What should credo do today?"
            , choices = self.actions
            )

        parser.add_argument("-a", "--account"
            , help = "The account to use (optionally use account@repo syntax)"
            )

        parser.add_argument("-u", "--user"
            , help = "The user to use (optionally use user@account@repo syntax, where account and repo are optional)"
            )

        parser.add_argument("-r", "--repo"
            , help = "The repo to use"
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

        credo = Credo()
        credo.setup(**vars(cred_args))
        return credo

    def parser_for_no_args(self, description, func):
        """Return a function that parses no arguments"""

        def parse_noargs(action, argv):
            """No args to parse"""
            parser = argparse.ArgumentParser(description=description)
            args = self.args_from_subparser(action, parser, argv)
            return args, func

        return parse_noargs

    def parse_help(self, action, argv):
        """Just prints help and quits"""
        # It's late, I'm tired....
        print "Help is not here"
        sys.exit(1)

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
        parser.add_argument("--half-life"
            , help = "Choose a half life for your new key"
            , choices = ["hour", "day", "week"]
            )
        args = self.args_from_subparser(action, parser, argv)
        return args, do_import

    def parse_remote(self, action, argv):
        """Options for setting an external remote for syncing with"""
        parser = argparse.ArgumentParser(description="Set up a remote for a repository")

        parser.add_argument("--version-with"
            , help = "Use this to make this repository versioned"
            , choices = ["nothing", "git"]
            )

        remote = parser.add_mutually_exclusive_group()
        remote.add_argument("--no-new-remote"
            , help = "Don't set a remote"
            , dest = "remote"
            , const = False
            , action = "store_const"
            )
        remote.add_argument("--remote"
            , help = "Set a particular remote"
            )

        args = self.args_from_subparser(action, parser, argv)
        return args, do_remote

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

