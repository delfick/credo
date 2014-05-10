import os

def _print_list_of_tuples(lst, prefix):
    """Helper for printing out a list of tuples"""
    if any(val for _, val in lst):
        print "{0}: {1}".format(prefix, " | ".join("{0}={1}".format(key, val) for key, val in lst if val))

def do_display(credulous, **kwargs):
    """Just print out the chosen creds"""
    for key, val in credulous.chosen.shell_exports():
        print "export {0}='{1}'".format(key, val)

def do_exec(credulous, command, **kwargs):
    """Exec some command with aws credentials in the environment"""
    environment = dict(os.environ)
    environment.update(dict(credulous.chosen.shell_exports()))
    os.execvpe(command[0], command, environment)

def do_import(credulous):
    """Import some creds"""
    credentials = credulous.make_credentials()
    credentials.save()

def do_showavailable(credulous, force_show_all=False, collapse_if_one=True, **kwargs):
    """Show all what available repos, accounts and users we have"""
    explorer = credulous.make_explorer()

    if force_show_all:
        completed, fltr = explorer.completed, []
    else:
        completed, fltr = explorer.filtered(repo=credulous.repo, account=credulous.account, user=credulous.user)

    _print_list_of_tuples(fltr, "Using the filters")

    headings = ["Repositories", "Accounts", "Users"]

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

    def display_creds(cred, indent=""):
        """Display info about the creds"""
        as_string = cred.as_string()
        for line in as_string.split('\n'):
            print "{0}{1}".format(indent * 3, line)

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
                display_creds(values, "    ")

    # Complain if no found credentials
    if not completed:
        print "Didn't find any credential files"
        return

    # Special case if we only found one
    if collapse_if_one:
        r = completed
        chain = []
        while True:
            if not r:
                break

            if len(r) > 1:
                break

            chain.append(r.keys()[0])
            r = r[r.keys()[0]]
            if not isinstance(r, list) and not isinstance(r, tuple) and not isinstance(r, dict):
                _print_list_of_tuples(zip(["repo", "account", "user"], chain), "Only found one set of credentials")
                display_creds(r)
                return

    # Or just do them all if found more than one
    result = get_displayable(completed, headings)
    display_result(result)

