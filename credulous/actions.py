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

def do_showavailable(credulous, **kwargs):
    """Show all what available repos, accounts and users we have"""
    directory_structure, completed = credulous.explore()
    structure = [("repos", "Repositories"), ("accounts", "Accounts"), ("users", "Users")]

    def get_displayable(root, chain, indent="", heading_chain=None, sofar=None, complete=None):
        """
        Return a structure for printing out our available credentials
        return as (heading, children)

        Where children is
            {child: (heading, grandchildren), child2: (heading, grandchildren)}
        """
        if complete is None:
            complete = completed

        if sofar is None:
            sofar = []

        if heading_chain is None:
            heading_chain = ["="]

        def get_indented(s, prefix=""):
            """Print the string with leading indentation"""
            return "{0}{1}{2}".format(indent, prefix, s)

        def get_underlined(s, underline):
            """Get the indented str with an indented underline"""
            if underline:
                return "{0}\n{1}".format(get_indented(s), get_indented(underline * len(s)))
            else:
                return "{0}:".format(get_indented(s, ">> "))

        if chain:
            category, heading = chain.pop(0)

            if any(child in complete for child in root[category]):
                heading_underline = None
                if heading_chain:
                    heading_underline = heading_chain.pop(0)

                children = {}
                for key, val in root[category].items():
                    if key in complete:
                        indented_key = get_indented(key)
                        children[indented_key] = get_displayable(val, list(chain), indent + "    ", list(heading_chain), list(sofar) + [indented_key], complete=complete[key])

                return get_underlined(heading, heading_underline), children
        else:
            if root and "/files/" in root and "credentials.json" in [os.path.basename(fle) for fle in root["/files/"]]:
                valid = complete
                for part in sofar:
                    if part not in valid:
                        valid[part] = {}
                    valid = valid[part]

    def display_result(result):
        """Display the result from get_displayable"""
        heading, children = result
        print ""
        print heading
        for child, values in children.items():
            print ""
            print child
            if values:
                display_result(values)

    result = get_displayable(directory_structure, structure)
    if not result:
        print "Didn't find any credential files"
    else:
        display_result(result)

