import sys

def ask_for_choice(needed, choices):
    """Ask for a value from some choices"""
    mapped = dict(enumerate(sorted(choices)))
    no_value = True
    while no_value:
        print >> sys.stderr, "Please choose a value from the following"
        for num, val in mapped.items():
            print >> sys.stderr, "{0}) {1}".format(num, val)

        sys.stderr.write(": ")
        sys.stderr.flush()
        response = raw_input()

        if response is None or not response.isdigit() or int(response) not in mapped:
            print >> sys.stderr, "Please choose a valid response ({0} is not valid)".format(response)
        else:
            no_value = False
            return mapped[int(response)]

def ask_for_choice_or_new(needed, choices):
    mapped = dict(enumerate(sorted(choices)))
    no_value = True
    while no_value:
        print >> sys.stderr, "Choose a {0}".format(needed)
        if mapped:
            maximum = max(mapped.keys())
            print >> sys.stderr, "Please choose a value from the following"
            num = -1
            for num, val in mapped.items():
                print >> sys.stderr, "{0}) {1}".format(num, val)
            print >> sys.stderr, "{0}) {1}".format(num+1, "Make your own value")

            sys.stderr.write(": ")
            sys.stderr.flush()
            response = raw_input()

            if response is None or not response.isdigit() or int(response) < 0 or int(response) < maximum:
                print >> sys.stderr, "Please choose a valid response ({0} is not valid)".format(response)
            else:
                no_value = False
                response = int(response)
                if response in mapped:
                    return mapped[response]
        else:
            no_value = False

        if not no_value:
            sys.stderr.write("Enter your custom value: ")
            sys.stderr.flush()
            return raw_input()
