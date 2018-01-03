#!/usr/bin/python

def pn_cli(module, switch=None):
    """
    Method to generate the cli portion to launch the Netvisor cli.
    :param module: The Ansible module to fetch username and password.
    :return: The cli string for further processing.
    """

    cli = '/usr/bin/cli --quiet -e '

    if switch:
        cli += ' switch ' + switch

    return cli

