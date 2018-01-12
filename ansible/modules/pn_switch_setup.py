#!/usr/bin/python
""" PN CLI switch-setup-modify """
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
module: pn_switch_setup
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to modify switch-setup.
description:
  - C(modify): modify switch setup
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - switch-setup configuration command.
    required: true
    choices: ['modify']
    type: str
  pn_force:
    description:
      - force analytics-store change even if it involves removing data
    required: false
    type: bool
  pn_dns_ip:
    description:
      - DNS IP address
    required: false
    type: str
  pn_mgmt_netmask:
    description:
      - netmask
    required: false
    type: str
  pn_gateway_ip6:
    description:
      - gateway IPv6 address
    required: false
    type: str
  pn_in_band_ip6_assign:
    description:
      - data IPv6 address assignment
    required: false
    choices: ['none', 'autoconf']
  pn_domain_name:
    description:
      - domain name
    required: false
    type: str
  pn_timezone:
    description:
      - timezone
    required: false
    type: str
  pn_in_band_netmask:
    description:
      - data in-band netmask
    required: false
    type: str
  pn_in_band_ip6:
    description:
      - data in-band IPv6 address
    required: false
    type: str
  pn_in_band_netmask_ip6:
    description:
      - data in-band IPv6 netmask
    required: false
    type: str
  pn_phone_home:
    description:
      - server-switch can contact update server
    required: false
    type: bool
  pn_mgmt_ip6_assignment:
    description:
      - IPv6 address assignment
    required: false
    choices: ['none', 'autoconf']
  pn_ntp_secondary_server:
    description:
      - Secondary NTP server
    required: false
    type: str
  pn_in_band_ip:
    description:
      - data in-band IP address
    required: false
    type: str
  pn_eula_accepted:
    description:
      - accept EULA
    required: false
    choices: ['true', 'false']
  pn_mgmt_ip:
    description:
      - management IP address
    required: false
    type: str
  pn_ntp_server:
    description:
      - NTP server
    required: false
    type: str
  pn_mgmt_ip_assignment:
    description:
      - IP address assignment
    required: false
    choices: ['none', 'dhcp']
  pn_date:
    description:
      - date
    required: false
    type: str
  pn_password:
    description:
      - plain text password
    required: false
    type: str
  pn_banner:
    description:
      - Banner to display on server-switch
    required: false
    type: str
  pn_dns_secondary_ip:
    description:
      - secondary DNS IP address
    required: false
    type: str
  pn_switch_name:
    description:
      - switch name
    required: false
    type: str
  pn_eula_timestamp:
    description:
      - EULA timestamp
    required: false
    type: str
  pn_mgmt_netmask_ip6:
    description:
      - IPv6 netmask
    required: false
    type: str
  pn_enable_host_ports:
    description:
      - Enable host ports by default
    required: false
    type: bool
  pn_mgmt_ip6:
    description:
      - IPv6 address
    required: false
    type: str
  pn_analytics_store:
    description:
      - type of disk storage for analytics
    required: false
    choices: ['default', 'optimized']
  pn_motd:
    description:
      - Message of the Day
    required: false
    type: str
  pn_gateway_ip:
    description:
      - gateway IPv4 address
    required: false
    type: str
"""

EXAMPLES = """
- name: Modify switch inband ipv6
  pn_switch_setup:
    pn_action: "modify" 
    pn_cliswitch: {{ inventory.hostname }} 
    pn_in_band_ip6: "2620:0:167f:b010::10/64"
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the switch-setup command.
  returned: always
  type: list
stderr:
  description: set of error responses from the switch-setup command.
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
    action = module.params['pn_action']
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)

    # Response in JSON format
    if err:
        module.fail_json(
            command=' '.join(cli),
            stderr=err.strip(),
            msg="switch-setup %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="switch-setup %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="switch-setup %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str', choices=['modify']),
            pn_force=dict(required=False, type='bool'),
            pn_dns_ip=dict(required=False, type='str'),
            pn_mgmt_netmask=dict(required=False, type='str'),
            pn_gateway_ip6=dict(required=False, type='str'),
            pn_in_band_ip6_assign=dict(required=False, type='str',
                                       choices=['none', 'autoconf']),
            pn_domain_name=dict(required=False, type='str'),
            pn_timezone=dict(required=False, type='str'),
            pn_in_band_netmask=dict(required=False, type='str'),
            pn_in_band_ip6=dict(required=False, type='str'),
            pn_in_band_netmask_ip6=dict(required=False, type='str'),
            pn_phone_home=dict(required=False, type='bool'),
            pn_mgmt_ip6_assignment=dict(required=False, type='str',
                                        choices=['none', 'autoconf']),
            pn_ntp_secondary_server=dict(required=False, type='str'),
            pn_in_band_ip=dict(required=False, type='str'),
            pn_eula_accepted=dict(required=False, type='str',
                                  choices=['true', 'false']),
            pn_mgmt_ip=dict(required=False, type='str'),
            pn_ntp_server=dict(required=False, type='str'),
            pn_mgmt_ip_assignment=dict(required=False, type='str',
                                       choices=['none', 'dhcp']),
            pn_date=dict(required=False, type='str'),
            pn_password=dict(required=False, type='str'),
            pn_banner=dict(required=False, type='str'),
            pn_dns_secondary_ip=dict(required=False, type='str'),
            pn_switch_name=dict(required=False, type='str'),
            pn_eula_timestamp=dict(required=False, type='str'),
            pn_mgmt_netmask_ip6=dict(required=False, type='str'),
            pn_enable_host_ports=dict(required=False, type='bool'),
            pn_mgmt_ip6=dict(required=False, type='str'),
            pn_analytics_store=dict(required=False, type='str',
                                    choices=['default', 'optimized']),
            pn_motd=dict(required=False, type='str'),
            pn_gateway_ip=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    switch = module.params['pn_cliswitch']
    mod_action = module.params['pn_action']
    force = module.params['pn_force']
    dns_ip = module.params['pn_dns_ip']
    mgmt_netmask = module.params['pn_mgmt_netmask']
    gateway_ip6 = module.params['pn_gateway_ip6']
    in_band_ip6_assign = module.params['pn_in_band_ip6_assign']
    domain_name = module.params['pn_domain_name']
    timezone = module.params['pn_timezone']
    in_band_netmask = module.params['pn_in_band_netmask']
    in_band_ip6 = module.params['pn_in_band_ip6']
    in_band_netmask_ip6 = module.params['pn_in_band_netmask_ip6']
    phone_home = module.params['pn_phone_home']
    mgmt_ip6_assignment = module.params['pn_mgmt_ip6_assignment']
    ntp_secondary_server = module.params['pn_ntp_secondary_server']
    in_band_ip = module.params['pn_in_band_ip']
    eula_accepted = module.params['pn_eula_accepted']
    mgmt_ip = module.params['pn_mgmt_ip']
    ntp_server = module.params['pn_ntp_server']
    mgmt_ip_assignment = module.params['pn_mgmt_ip_assignment']
    date = module.params['pn_date']
    password = module.params['pn_password']
    banner = module.params['pn_banner']
    dns_secondary_ip = module.params['pn_dns_secondary_ip']
    switch_name = module.params['pn_switch_name']
    eula_timestamp = module.params['pn_eula_timestamp']
    mgmt_netmask_ip6 = module.params['pn_mgmt_netmask_ip6']
    enable_host_ports = module.params['pn_enable_host_ports']
    mgmt_ip6 = module.params['pn_mgmt_ip6']
    analytics_store = module.params['pn_analytics_store']
    motd = module.params['pn_motd']
    gateway_ip = module.params['pn_gateway_ip']

    # Building the CLI command string
    cli = pn_cli(module, switch)
    cli += ' switch-setup-' + mod_action
    if mod_action in ['modify']:
        if force:
            if force is True:
                cli += ' force '
            else:
                cli += ' no-force '
        if dns_ip:
            cli += ' dns-ip ' + dns_ip
        if mgmt_netmask:
            cli += ' mgmt-netmask ' + mgmt_netmask
        if gateway_ip6:
            cli += ' gateway-ip6 ' + gateway_ip6
        if in_band_ip6_assign:
            cli += ' in-band-ip6-assign ' + in_band_ip6_assign
        if domain_name:
            cli += ' domain-name ' + domain_name
        if timezone:
            cli += ' timezone ' + timezone
        if in_band_netmask:
            cli += ' in-band-netmask ' + in_band_netmask
        if in_band_ip6:
            cli += ' in-band-ip6 ' + in_band_ip6
        if in_band_netmask_ip6:
            cli += ' in-band-netmask-ip6 ' + in_band_netmask_ip6
        if phone_home:
            if phone_home is True:
                cli += ' phone-home '
            else:
                cli += ' no-phone-home '
        if mgmt_ip6_assignment:
            cli += ' mgmt-ip6-assignment ' + mgmt_ip6_assignment
        if ntp_secondary_server:
            cli += ' ntp-secondary-server ' + ntp_secondary_server
        if in_band_ip:
            cli += ' in-band-ip ' + in_band_ip
        if eula_accepted:
            cli += ' eula-accepted ' + eula_accepted
        if mgmt_ip:
            cli += ' mgmt-ip ' + mgmt_ip
        if ntp_server:
            cli += ' ntp-server ' + ntp_server
        if mgmt_ip_assignment:
            cli += ' mgmt-ip-assignment ' + mgmt_ip_assignment
        if date:
            cli += ' date ' + date
        if password:
            cli += ' password ' + password
        if banner:
            cli += ' banner ' + banner
        if dns_secondary_ip:
            cli += ' dns-secondary-ip ' + dns_secondary_ip
        if switch_name:
            cli += ' switch-name ' + switch_name
        if eula_timestamp:
            cli += ' eula_timestamp ' + eula_timestamp
        if mgmt_netmask_ip6:
            cli += ' mgmt-netmask-ip6 ' + mgmt_netmask_ip6
        if enable_host_ports:
            if enable_host_ports is True:
                cli += ' enable-host-ports '
            else:
                cli += ' disable-host-ports '
        if mgmt_ip6:
            cli += ' mgmt-ip6 ' + mgmt_ip6
        if analytics_store:
            cli += ' analytics-store ' + analytics_store
        if motd:
            cli += ' motd ' + motd
        if gateway_ip:
            cli += ' gateway-ip ' + gateway_ip

    run_cli(module, cli)

if __name__ == '__main__':
    main()
