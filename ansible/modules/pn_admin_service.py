#!/usr/bin/python
""" PN CLI admin-service-modify """
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

import shlex
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pn_nvos import pn_cli

DOCUMENTATION = """
---
module: pn_admin_service
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to modify admin-service.
description:
  - C(modify): modify services on the server-switch
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  action:
    description:
      - admin-service configuration command.
    required: true
    choices: ['modify']
    type: str
  pn_web:
    description:
      - Web (HTTP) - enable or disable
    required: false
    type: bool
  pn_web_ssl:
    description:
      - Web SSL (HTTPS) - enable or disable
    required: false
    type: bool
  pn_snmp:
    description:
      - Simple Network Monitoring Protocol (SNMP) - enable or disable
    required: false
    type: bool
  pn_web_port:
    description:
      - Web (HTTP) port - enable or disable
    required: false
    type: str
  pn_web_ssl_port:
    description:
      - Web SSL (HTTPS) port - enable or disable
    required: false
    type: str
  pn_nfs:
    description:
      - Network File System (NFS) - enable or disable
    required: false
    type: bool
  pn_ssh:
    description:
      - Secure Shell - enable or disable
    required: false
    type: bool
  pn_web_log:
    description:
      - Web logging - enable or disable
    required: false
    type: bool
  pn__if:
    description:
      - administrative service interface
    required: false
    type: str
  pn_icmp:
    description:
      - Internet Message Control Protocol (ICMP) - enable or disable
    required: false
    type: bool
  pn_net_api:
    description:
      - Netvisor API - enable or disable APIs
    required: false
    type: bool
"""

EXAMPLES = """
- name: admin service functionality
  pn_admin_service:
    action: "modify"
    pn_web: False
    pn__if: "mgmt"
    pn_web_ssl: False
    pn_snmp: True
    pn_net_api: True
    pn_icmp: True
    pn_ssh: True
    pn_nfs: True
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the admin-service command.
  returned: always
  type: list
stderr:
  description: set of error responses from the admin-service command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
"""


def run_cli(module, cli):
    """
    This method executes the cli command on the target node(s) and returns the
    output. The module then exits based on the output.
    :param cli: the complete cli string to be executed on the target node(s).
    :param module: The Ansible module to fetch command
    """
    action = module.params['action']
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)

    # Response in JSON format
    if err:
        module.fail_json(
            command=' '.join(cli),
            stderr=err.strip(),
            msg="admin-service %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="admin-service %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="admin-service %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            action=dict(required=True, type='str', choices=['modify']),
            pn_web=dict(required=False, type='bool'),
            pn_web_ssl=dict(required=False, type='bool'),
            pn_snmp=dict(required=False, type='bool'),
            pn_web_port=dict(required=False, type='str'),
            pn_web_ssl_port=dict(required=False, type='str'),
            pn_nfs=dict(required=False, type='bool'),
            pn_ssh=dict(required=False, type='bool'),
            pn_web_log=dict(required=False, type='bool'),
            pn__if=dict(required=False, type='str'),
            pn_icmp=dict(required=False, type='bool'),
            pn_net_api=dict(required=False, type='bool'),
        )
    )

    # Accessing the arguments
    switch = module.params['pn_cliswitch']
    mod_action = module.params['action']
    web = module.params['pn_web']
    web_ssl = module.params['pn_web_ssl']
    snmp = module.params['pn_snmp']
    web_port = module.params['pn_web_port']
    web_ssl_port = module.params['pn_web_ssl_port']
    nfs = module.params['pn_nfs']
    ssh = module.params['pn_ssh']
    web_log = module.params['pn_web_log']
    _if = module.params['pn__if']
    icmp = module.params['pn_icmp']
    net_api = module.params['pn_net_api']

    # Building the CLI command string
    cli = pn_cli(module, switch)
    cli += ' admin-service-' + mod_action
    if mod_action in ['modify']:
        if _if:
            cli += ' if %s ' % _if
        if web:
            if web is True:
                cli += ' web '
            else:
                cli += ' no-web '
        if web_ssl:
            if web_ssl is True:
                cli += ' web-ssl '
            else:
                cli += ' no-web-ssl '
        if snmp:
            if snmp is True:
                cli += ' snmp '
            else:
                cli += ' no-snmp '
        if web_port:
            cli += ' web-port ' + web_port
        if web_ssl_port:
            cli += ' web-ssl-port ' + web_ssl_port
        if nfs:
            if nfs is True:
                cli += ' nfs '
            else:
                cli += ' no-nfs '
        if ssh:
            if ssh is True:
                cli += ' ssh '
            else:
                cli += ' no-ssh '
        if web_log:
            if web_log is True:
                cli += ' web-log '
            else:
                cli += ' no-web-log '
        if icmp:
            if icmp is True:
                cli += ' icmp '
            else:
                cli += ' no-icmp '
        if net_api:
            if net_api is True:
                cli += ' net-api '
            else:
                cli += ' no-net-api '

    run_cli(module, cli)

if __name__ == '__main__':
    main()
