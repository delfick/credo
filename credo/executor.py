from credo.actions import do_exports, do_exec, do_showavailable, do_import, do_rotate, do_current, do_remote, do_synchronize, do_capture, do_env, do_unset
from credo.errors import CredoError, NoExecCommand
from credo.asker import secret_sources
from credo.overview import Credo
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

def sourceable_if(action_is):
    """Set a parser as sourceable if the action is as specified"""
    def wrapper(func):
        func.sourceable_if = action_is
        return func
    return wrapper

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
        cred_args, action, action_args = self.split_argv(argv)
        if "--version" in cred_args:
            self.show_version_and_quit()

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
            , "rotate": self.parse_rotate
            , "version": self.parse_version
            , "sourceable": self.parse_sourceable

            , "env": self.parse_env
            , "capture": self.parse_env

            , "unset": self.parser_for_no_args("Unset credo environment variables", do_unset, sourceable=True)
            , "inject": self.parser_for_no_args("Print out export statements for your aws creds", do_exports, sourceable=True)
            , "exports": self.parser_for_no_args("Print out export statements for your aws creds", do_exports)
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

        parser.add_argument("--version"
            , help = "Print version and quit"
            , dest = "show_version"
            , action = "store_true"
            )

        parser.add_argument("--boto-debug"
            , help = "Show debug log messages for boto"
            , action = "store_true"
            )

        return parser

    def show_version_and_quit(self):
        """Show the version and quit"""
        print("Credo {0}".format(VERSION))
        sys.exit(0)

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

    def parser_for_no_args(self, description, func, sourceable=False):
        """Return a function that parses no arguments"""

        def parse_noargs(action, argv):
            """No args to parse"""
            parser = argparse.ArgumentParser(description=description)
            if sourceable:
                parser.add_argument("--no-sourcing"
                    , help = "Tell credo sourceable not to source this output"
                    , action = "store_true"
                    )
            args = self.args_from_subparser(action, parser, argv)
            return args, func
        parse_noargs.sourceable = sourceable

        return parse_noargs

    def parse_help(self, action, argv):
        """Just prints help and quits"""
        # It's late, I'm tired....
        print "Try the --help option"
        sys.exit(1)

    def parse_version(self, action, argv):
        """Just show the version and quit"""
        self.show_version_and_quit()

    @sourceable_if("env")
    def parse_env(self, action, argv):
        """Capture/display environment variables"""
        parser = argparse.ArgumentParser(description="Capture environment variables")

        def env_spec(key):
            """Specification for an environment variable"""
            if "=" not in key:
                if key not in os.environ:
                    raise argparse.ArgumentTypeError("The specified environment variable {0} isn't in the current environment".format(key))
                else:
                    return (key, os.environ[key])
            else:
                k, v = key.split('=', 1)
                return (k.strip(), v.strip())

        if action == "capture":
            parser.add_argument("--env"
                , help = "Capture this environment variable"
                , type = env_spec
                , action = "append"
                )

            parser.add_argument("--remove-env"
                , help = "Remove this env from our capture"
                , action = "append"
                )

        chooser = parser.add_mutually_exclusive_group()

        chooser.add_argument("--all-accounts"
            , help = "Capture environment variables for our chosen repository"
            , action = "store_true"
            )

        chooser.add_argument("--all-users"
            , help = "Capture environment variables for our chosen account"
            , action = "store_true"
            )

        chooser.add_argument("--find-user"
            , help = "Find a particular user"
            , action = "store_true"
            )

        if action == "env":
            parser.add_argument("--no-sourcing"
                , help = "Make credo sourceable say this is not sourceable"
                , action = "store_true"
                )

        args = self.args_from_subparser(action, parser, argv)

        func = do_env
        if action == "capture":
            func = do_capture
        return args, func

    def parse_rotate(self, action, argv):
        """Rotate our credentials"""
        parser = argparse.ArgumentParser(description="Rotate the credentials")
        parser.add_argument("--force"
            , help = "Force expire everything"
            , action = "store_true"
            )
        args = self.args_from_subparser(action, parser, argv)
        return args, do_rotate

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

    def parse_sourceable(self, action, argv):
        """Use CliParser to determine if these args given to credo produces a result that can be sourced into the shell"""
        parser = argparse.ArgumentParser(description="Entrypoint for scripts to determine if provided arguments, when given to credo, produces a result that should be sourced into the shell")
        if argv and argv[0] in ("--help", "-h"):
            try:
                self.args_from_subparser(action, parser, argv)
            except SystemExit:
                # Want to quit with an error code
                # So bash helper doesn't source the --help output
                sys.exit(1)
        else:
            if not argv:
                sys.exit(1)
            else:
                _, action, action_args = CliParser().split_argv(argv)
                if "--no-sourcing" not in action_args:
                    if action and action in self.actions:
                        parser = self.actions[action]
                        if getattr(parser, "sourceable", False):
                            sys.exit(0)
                        elif getattr(parser, "sourceable_if", None) == action:
                            sys.exit(0)

                # Otherwise, not sourceable
                sys.exit(1)

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

