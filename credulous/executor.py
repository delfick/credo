from credulous.actions import do_display, do_exec, do_showavailable, do_import, do_rotate
from credulous.errors import CredulousError, NoExecCommand
from credulous.overview import Credulous

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
        Get us (credulous, kwargs, function)

        Where credulous is an overview object of our credulous collection

        kwargs is the extra arguments to call the function with

        And function is what we want to call with the kwargs
        The function should have the signature function(credulous, **kwargs)
        """
        cred_args, action, action_args = self.split_argv()
        credulous = self.make_credulous(cred_args, action)
        kwargs, function = self.actions[action](action, action_args)
        return credulous, kwargs, function

    @property
    def actions(self):
        return {
              "help": self.parse_help
            , "exec": self.parse_exec
            , "show": self.parse_show
            , "import": self.parse_import
            , "rotate": self.parse_rotate
            , "display": self.parse_display
            }

    def cred_parser(self):
        """Parser for all the common credulous options"""
        parser = argparse.ArgumentParser(description="Credulous executor")

        parser.add_argument("action"
            , help = "What should credulous do today?"
            , choices = self.actions
            )

        parser.add_argument("--account"
            , help = "The account to use"
            )

        parser.add_argument("--user"
            , help = "The user to use"
            )

        parser.add_argument("--repo"
            , help = "The repo to use"
            )

        return parser

    def args_from_subparser(self, action, parser, argv):
        """Get us args from our parser as a dictionary and make sure our usage statement is nice"""
        cred_usage = self.cred_parser().format_usage().split(":", 1)[1].strip().split("\n")[0]
        subparser_usage = parser.format_usage()
        subparser_usage = subparser_usage[subparser_usage.index(parser.prog)+len(parser.prog):].strip()
        parser.usage = "{0} <|| {1} ||> {2}".format(cred_usage, action, subparser_usage)
        return vars(parser.parse_args(argv))

    def make_credulous(self, cred_args, expected_action):
        """Make a Credulous object that knows things"""
        cred_parser = self.cred_parser()
        cred_args = cred_parser.parse_args(cred_args)
        if cred_args.action != expected_action:
            raise CredulousError("Well this is weird, I thought the action was different than it turned out to be", expected=expected_action, parsed=cred_args.action)

        credulous = Credulous()
        credulous.find_options(**vars(cred_args))
        return credulous

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
        args = self.args_from_subparser(action, parser, argv)
        return args, do_import

    def parse_rotate(self, action, argv):
        """Rotate doesn't have any arguments yet"""
        parser = argparse.ArgumentParser(description="Rotate amazon secrets")
        args = self.args_from_subparser(action, parser, argv)
        return args, do_rotate

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
    setup_logging()

    try:
        credulous, kwargs, function = CliParser().parse_args(argv)
        function(credulous, **kwargs)
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

