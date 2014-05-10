import copy
import os

def do_display(credulous, **kwargs):
    """Just print out the chosen creds"""
    access_key, secret_key = credulous.current_creds
    exportable = lambda key, val: "export {0}='{1}'".format(key, val)
    maybe = lambda key: getattr(credulous, key, None)

    print exportable("AWS_ACCESS_KEY_ID", access_key)
    print exportable("AWS_SECRET_ACCESS_KEY", secret_key)
    print exportable("CREDULOUS_CURRENT_REPO", maybe("repo"))
    print exportable("CREDULOUS_CURRENT_ACCOUNT", maybe("account"))
    print exportable("CREDULOUS_CURRENT_USER", maybe("user"))

def do_exec(credulous, command, **kwargs):
    """Exec some command with aws credentials in the environment"""
    access_key, secret_key = credulous.current_creds
    environment = dict(os.environ)
    environment.update(AWS_ACCESS_KEY_ID=access_key, AWS_SECRET_ACCESS_KEY=secret_key)
    os.execvpe(command[0], command, environment)

def do_showone(credulous, **kwargs):
    """Show info about one of the creds"""
    print credulous.chosen.as_string()

def do_showavailable(credulous, **kwargs):
    """Show all what available repos, accounts and users we have"""
    directory_structure, completed = credulous.explore()
    headings = ["Repositories", "Accounts", "Users"]

    completed = copy.deepcopy(completed)
    if credulous.user:
        for repo, accounts in completed.items():
            for account, users in accounts.items():
                for user in users.keys():
                    if user != credulous.user:
                        del users[user]

    for repo, accounts in completed.items():
        for account, users in accounts.items():
            if credulous.account and account:
                del accounts[account]
            if not users and account in accounts:
                del accounts[account]

    for repo, accounts in completed.items():
        if credulous.repo and repo != credulous.repo:
            del completed[repo]
        if not accounts and repo in completed:
            del completed[repo]

    def get_displayable(root, headings, indent="", underline_chain=None, sofar=None):
        """
        Return a structure for printing out our available credentials
        return as (heading, children)

        Where children is
            {child: (heading, grandchildren), child2: (heading, grandchildren)}
        """
        if sofar is None:
            sofar = []

        if underline_chain is None:
            underline_chain = ["="]

        def get_indented(s, prefix=""):
            """Print the string with leading indentation"""
            return "{0}{1}{2}".format(indent, prefix, s)

        def get_underlined(s, underline):
            """Get the indented str with an indented underline"""
            if underline:
                return "{0}\n{1}".format(get_indented(s), get_indented(underline * len(s)))
            else:
                return "{0}:".format(get_indented(s, ">> "))

        if not headings:
            return root
        else:
            heading = headings.pop(0)

            heading_underline = None
            if underline_chain:
                heading_underline = underline_chain.pop(0)

            children = {}
            for key, val in root.items():
                indented_key = get_indented(key)
                children[indented_key] = get_displayable(val, list(headings), indent + "    ", list(underline_chain), list(sofar) + [indented_key])

            if not children:
                return None
            return get_underlined(heading, heading_underline), children

    def display_result(result):
        """Display the result from get_displayable"""
        heading, children = result
        print ""
        print heading
        for child, values in children.items():
            print ""
            print child
            if isinstance(values, list) or isinstance(values, tuple) or isinstance(values, dict):
                display_result(values)
            elif values:
                as_string = values.as_string()
                for line in as_string.split('\n'):
                    print "{0}{1}".format("    " * 3, line)

    result = get_displayable(completed, headings)
    if not result:
        print "Didn't find any credential files"
        filters = [("repo", credulous.repo), ("account", credulous.account), ("user", credulous.user)]
        if any(val for _, val in filters):
            print "Had a filter of: {0}".format(" | ".join("{0}={1}".format(key, val) for key, val in filters if val))

    else:
        display_result(result)

