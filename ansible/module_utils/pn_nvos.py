#!/usr/bin/python

def pn_cli(module, switch=None, username=None, password=None):
    """
    Method to generate the cli portion to launch the Netvisor cli.
    :param module: The Ansible module to fetch username and password.
    :return: The cli string for further processing.
    """

    cli = '/usr/bin/cli --quiet -e --no-login-prompt '

    if username and password:
        cli += '--user "%s":"%s" ' % (username, password)
    if switch:
        cli += ' switch ' + switch

    return cli
