#!/usr/bin/python
""" PN Fabric Creation """
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
import time

from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = """
---
module: pn_ztp_initial_setup
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: Module to perform fabric creation/join.
description:
    Zero Touch Provisioning (ZTP) allows you to provision new switches in your
    network automatically, without manual intervention.
    It performs following steps:
        - Disable STP
        - Enable all ports
        - Create/Join fabric
        - Enable STP
options:
    pn_cliusername:
      description:
        - Provide login username if user is not root.
      required: False
      type: str
    pn_clipassword:
      description:
        - Provide login password if user is not root.
      required: False
      type: str
    pn_fabric_name:
      description:
        - Specify name of the fabric.
      required: False
      type: str
    pn_fabric_network:
      description:
        - Specify fabric network type as either mgmt or in-band.
      required: False
      type: str
      choices: ['mgmt', 'in-band']
      default: 'mgmt'
    pn_fabric_control_network:
      description:
        - Specify fabric control network as either mgmt or in-band.
      required: False
      type: str
      choices: ['mgmt', 'in-band']
      default: 'mgmt'
    pn_toggle_port_speed:
      description:
        - Flag to indicate if 40g/100g ports should be converted to 10g/25g ports or not.
      required: False
      default: True
      type: bool
    pn_spine_list:
      description:
        - Specify list of Spine hosts
      required: False
      type: list
    pn_leaf_list:
      description:
        - Specify list of leaf hosts
      required: False
      type: list
    pn_inband_ip:
      description:
        - Inband ips to be assigned to switches starting with this value.
      required: False
      default: 172.16.0.0/24.
      type: str
    pn_current_switch:
      description:
        - Name of the switch on which this task is currently getting executed.
      required: False
      type: str
    pn_static_setup:
      description:
        - Flag to indicate if static values should be assign to
        following switch setup params.
      required: False
      default: False
      type: bool
    pn_mgmt_ip:
      description:
        - Specify MGMT-IP value to be assign if pn_static_setup is True.
      required: False
      type: str
    pn_mgmt_ip_subnet:
      description:
        - Specify subnet mask for MGMT-IP value to be assign if
        pn_static_setup is True.
      required: False
      type: str
    pn_gateway_ip:
      description:
        - Specify GATEWAY-IP value to be assign if pn_static_setup is True.
      required: False
      type: str
    pn_dns_ip:
      description:
        - Specify DNS-IP value to be assign if pn_static_setup is True.
      required: False
      type: str
    pn_dns_secondary_ip:
      description:
        - Specify DNS-SECONDARY-IP value to be assign if pn_static_setup is True
      required: False
      type: str
    pn_domain_name:
      description:
        - Specify DOMAIN-NAME value to be assign if pn_static_setup is True.
      required: False
      type: str
    pn_ntp_server:
      description:
        - Specify NTP-SERVER value to be assign if pn_static_setup is True.
      required: False
      type: str
    pn_web_api:
      description:
        - Flag to enable web api.
      default: True
      type: bool
    pn_stp:
      description:
        - Flag to enable STP at the end.
      required: False
      default: True
      type: bool
    pn_autotrunk:
      description:
        - Flag to enable/disable auto-trunk setting.
      required: False
      choices: ['enable', 'disable']
      type: str
    pn_autoneg:
      description:
        - Flag to enable/disable auto-neg for T2+ platforms.
      required: False
      type: bool
"""

EXAMPLES = """
- name: Fabric creation/join
    pn_fabric_creation:
      pn_cliusername: "{{ USERNAME }}"
      pn_clipassword: "{{ PASSWORD }}"
      pn_fabric_name: 'ztp-fabric'
      pn_current_switch: "{{ inventory_hostname }}"
      pn_spine_list: "{{ groups['spine'] }}"
      pn_leaf_list: "{{ groups['leaf'] }}"
"""

RETURN = """
summary:
  description: It contains output of each configuration along with switch name.
  returned: always
  type: str
changed:
  description: Indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
unreachable:
  description: Indicates whether switch was unreachable to connect.
  returned: always
  type: bool
failed:
  description: Indicates whether or not the execution failed on the target.
  returned: always
  type: bool
exception:
  description: Describes error/exception occurred while executing CLI command.
  returned: always
  type: str
task:
  description: Name of the task getting executed on switch.
  returned: always
  type: str
msg:
  description: Indicates whether configuration made was successful or failed.
  returned: always
  type: str
"""

CHANGED_FLAG = []


def pn_cli(module):
    """
    Method to generate the cli portion to launch the Netvisor cli.
    :param module: The Ansible module to fetch username and password.
    :return: The cli string for further processing.
    """
    username = module.params['pn_cliusername']
    password = module.params['pn_clipassword']

    if username and password:
        cli = '/usr/bin/cli --quiet --user %s:%s ' % (username, password)
    else:
        cli = '/usr/bin/cli --quiet '

    return cli


def run_cli(module, cli):
    """
    Method to execute the cli command on the target node(s) and returns the
    output.
    :param module: The Ansible module to fetch input parameters.
    :param cli: The complete cli string to be executed on the target node(s).
    :return: Output/Error or Success msg depending upon the response from cli.
    """
    results = []
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)

    if out:
        return out
    if err:
        json_msg = {
            'switch': module.params['pn_current_switch'],
            'output': u'Operation Failed: {}'.format(' '.join(cli))
        }
        results.append(json_msg)
        module.exit_json(
            unreachable=False,
            failed=True,
            exception=err.strip(),
            summary=results,
            task='Fabric creation',
            msg='Fabric creation failed',
            changed=False
        )
    else:
        return 'Success'


def make_switch_setup_static(module):
    """
    Method to assign static values to different switch setup parameters.
    :param module: The Ansible module to fetch input parameters.
    """
    mgmt_ip = module.params['pn_mgmt_ip']
    mgmt_ip_subnet = module.params['pn_mgmt_ip_subnet']
    gateway_ip = module.params['pn_gateway_ip']
    dns_ip = module.params['pn_dns_ip']
    dns_secondary_ip = module.params['pn_dns_secondary_ip']
    domain_name = module.params['pn_domain_name']
    ntp_server = module.params['pn_ntp_server']
    cli = pn_cli(module)
    cli += ' switch-setup-modify '

    if mgmt_ip:
        ip = mgmt_ip + '/' + mgmt_ip_subnet
        cli += ' mgmt-ip ' + ip

    if gateway_ip:
        cli += ' gateway-ip ' + gateway_ip

    if dns_ip:
        cli += ' dns-ip ' + dns_ip

    if dns_secondary_ip:
        cli += ' dns-secondary-ip ' + dns_secondary_ip

    if domain_name:
        cli += ' domain-name ' + domain_name

    if ntp_server:
        cli += ' ntp-server ' + ntp_server

    clicopy = cli
    if clicopy.split('switch-setup-modify')[1] != ' ':
        run_cli(module, cli)


def update_switch_names(module, switch_name):
    """
    Method to update switch names.
    :param module: The Ansible module to fetch input parameters.
    :param switch_name: Name to assign to the switch.
    :return: String describing switch name got modified or not.
    """
    cli = pn_cli(module)
    cli += ' switch-setup-show format switch-name '
    if switch_name == run_cli(module, cli).split()[1]:
        return ' Switch name is same as hostname! '
    else:
        cli = pn_cli(module)
        cli += ' switch-setup-modify switch-name ' + switch_name
        run_cli(module, cli)
        return ' Updated switch name to match hostname! '


def modify_stp_local(module, modify_flag):
    """
    Method to enable/disable STP (Spanning Tree Protocol) on a switch.
    :param module: The Ansible module to fetch input parameters.
    :param modify_flag: Enable/disable flag to set.
    :return: The output of run_cli() method.
    """
    cli = pn_cli(module)
    cli += ' switch-local stp-show format enable '
    current_state = run_cli(module, cli).split()[1]

    if current_state == 'yes':
        cli = pn_cli(module)
        cli += ' switch-local stp-modify ' + modify_flag
        return run_cli(module, cli)
    else:
        return ' Already modified '


def ports_modify_jumbo(module, modify_flag):
    """
    Method to enable/disable Jumbo flag on a switch ports.
    :param module: The Ansible module to fetch input parameters.
    :param modify_flag: Enable/disable flag to set.
    :return: The output of run_cli() method.
    """
    cli = pn_cli(module)
    clicopy = cli
    trunk_ports = []
    cli += ' switch-local port-show format port,trunk status trunk no-show-headers'
    cli_out = run_cli(module, cli)
    if cli_out == 'Success':
        pass
    else:
        cli_out = cli_out.strip().split('\n')
        for output in cli_out:
            output = output.strip().split()
            port, trunk_name = output[0], output[1]
            trunk_ports.append(port)
            cli = clicopy
            cli += 'trunk-modify name %s jumbo ' % trunk_name
            run_cli(module, cli)

    cli = clicopy
    cli += ' switch-local port-config-show format port no-show-headers'
    ports = run_cli(module, cli).split()
    ports_to_modify = list(set(ports) - set(trunk_ports))
    ports_to_modify = ','.join(ports_to_modify)
    cli = clicopy
    cli += ' switch-local port-config-modify port %s %s' \
           % (ports_to_modify, modify_flag)
    return run_cli(module, cli)


def configure_control_network(module, network):
    """
    Method to configure the fabric control network.
    :param module: The Ansible module to fetch input parameters.
    :param network: It can be in-band or management.
    :return: The output of run_cli() method.
    """
    cli = pn_cli(module)
    cli += ' fabric-info format control-network '
    current_control_network = run_cli(module, cli).split()[1]

    if current_control_network != network:
        cli = pn_cli(module)
        cli += ' fabric-local-modify control-network ' + network
        return run_cli(module, cli)
    else:
        return ' Already configured '


def enable_ports(module):
    """
    Method to enable all ports of a switch.
    :param module: The Ansible module to fetch input parameters.
    :return: The output of run_cli() method or None.
    """
    cli = pn_cli(module)
    clicopy = cli
    cli += ' switch-local port-config-show format enable no-show-headers '
    if 'off' in run_cli(module, cli).split():
        cli = clicopy
        cli += ' switch-local port-config-show format port no-show-headers '
        out = run_cli(module, cli)

        cli = clicopy
        cli += ' switch-local port-config-show format port speed 40g '
        cli += ' no-show-headers '
        out_40g = run_cli(module, cli)
        out_remove10g = []

        if len(out_40g) > 0 and out_40g != 'Success':
            out_40g = out_40g.split()
            out_40g = list(set(out_40g))
            if len(out_40g) > 0:
                for port_number in out_40g:
                    out_remove10g.append(str(int(port_number) + int(1)))
                    out_remove10g.append(str(int(port_number) + int(2)))
                    out_remove10g.append(str(int(port_number) + int(3)))

        if out:
            out = out.split()
            out = set(out) - set(out_remove10g)
            out = list(out)
            if out:
                ports = ','.join(out)
                cli = clicopy
                cli += ' switch-local port-config-modify port %s enable ' % (
                    ports)
                return run_cli(module, cli)
    else:
        return None


def create_or_join_fabric(module, fabric_name, fabric_network):
    """
    Method to create/join a fabric with default fabric type as mgmt.
    :param module: The Ansible module to fetch input parameters.
    :param fabric_name: Name of the fabric to create/join.
    :param fabric_network: Type of the fabric to create (mgmt/in-band).
    Default value: mgmt
    :return: The output of run_cli() method.
    """
    cli = pn_cli(module)
    clicopy = cli

    cli += ' fabric-show format name no-show-headers '
    existing_fabrics = run_cli(module, cli).split()

    if fabric_name not in existing_fabrics:
        cli = clicopy
        cli += ' fabric-create name ' + fabric_name
        cli += ' fabric-network ' + fabric_network
        return run_cli(module, cli)
    else:
        cli = clicopy
        cli += ' fabric-info format name no-show-headers'
        cli = shlex.split(cli)
        rc, out, err = module.run_command(cli)

        if err:
            cli = clicopy
            cli += ' fabric-join name ' + fabric_name
        elif out:
            present_fabric_name = out.split()
            if present_fabric_name[1] not in existing_fabrics:
                cli = clicopy
                cli += ' fabric-join name ' + fabric_name
            else:
                return 'Switch already in the fabric'

    return run_cli(module, cli)


def modify_auto_neg(module):
    """
    Module to enable/disable auto-neg for T2+ platforms.
    :param module:
    :return: Nothing
    """
    current_switch = module.params['pn_current_switch']
    spines = module.params['pn_spine_list']

    if current_switch in spines:
        cli = pn_cli(module)
        cli += ' switch-local bezel-portmap-show format port no-show-headers '
        cli = shlex.split(cli)
        out = module.run_command(cli)[1]
        all_ports = out.splitlines()
        all_ports = [port.strip() for port in all_ports]
        time.sleep(1)

        cli = pn_cli(module)
        cli += ' switch-local lldp-show format local-port no-show-headers '
        cli = shlex.split(cli)
        out = module.run_command(cli)[1]
        lldp_ports = out.splitlines()
        lldp_ports = [port.strip() for port in lldp_ports]
        time.sleep(1)

        idle_ports = list(set(all_ports) ^ set(lldp_ports))
        cli = pn_cli(module)
        cli += ' switch-local port-config-modify port %s autoneg ' % ','.join(idle_ports)
        cli = shlex.split(cli)
        module.run_command(cli)
        time.sleep(1)

        cli = pn_cli(module)
        cli += ' switch-local lldp-show format local-port no-show-headers '
        cli = shlex.split(cli)
        out = module.run_command(cli)[1]
        lldp_ports = out.splitlines()
        lldp_ports = [port.strip() for port in lldp_ports]
        time.sleep(1)

        idle_ports = list(set(all_ports) ^ set(lldp_ports))
        cli = pn_cli(module)
        cli += ' switch-local port-config-modify port %s no-autoneg ' % ','.join(idle_ports)
        module.run_command(cli)
        time.sleep(1)

        return "Auto-neg Configured"


def modify_auto_trunk(module, flag):
    """
    Method to enable/disable auto trunk setting of a switch.
    :param module: The Ansible module to fetch input parameters.
    :param flag: Enable/disable flag for the cli command.
    :return: The output of run_cli() method.
    """
    cli = pn_cli(module)
    if flag.lower() == 'enable':
        cli += ' system-settings-modify auto-trunk '
        return run_cli(module, cli)
    elif flag.lower() == 'disable':
        cli += ' system-settings-modify no-auto-trunk '
        return run_cli(module, cli)


def enable_web_api(module):
    """
    Method to enable web api on switches.
    :param module: The Ansible module to fetch input parameters.
    """
    cli = pn_cli(module)
    cli += ' admin-service-modify web if mgmt '
    run_cli(module, cli)


def toggle(module, ports, local_ports, toggle_speed, port_speed, max_ports):
    """
    Method to toggle 40g/100g ports to 10g/25g ports.
    :param module: The Ansible module to fetch input parameters.
    :return: The output messages for assignment.
    """
    output = ''
    splitter_ports = []
    cli = pn_cli(module)
    clicopy = cli

    ports_to_modify = list(set(ports) - set(local_ports))

    for port in ports_to_modify:
        next_port = str(int(port) + 1)
        cli = clicopy
        cli += ' switch-local'
        cli += ' port-show port %s format bezel-port' % next_port
        cli += ' no-show-headers'
        bezel_port = run_cli(module, cli).split()[0]

        if '.2' in bezel_port:
            end_port = int(port) + 3
            range_port = port + '-' + str(end_port)

            cli = clicopy
            cli += ' switch-local port-config-modify port %s ' % port
            cli += ' disable '
            output += 'port ' + port + ' disabled'
            output += run_cli(module, cli)

            cli = clicopy
            cli += ' switch-local port-config-modify port %s ' % port
            cli += ' speed %s ' % toggle_speed
            output += 'port ' + port + ' converted to %s' % toggle_speed
            output += run_cli(module, cli)

            cli = clicopy
            cli += ' switch-local port-config-modify port %s ' % range_port
            cli += ' enable '
            output += 'port range_port ' + range_port + '  enabled'
            output += run_cli(module, cli)

            splitter_ports.append(range(int(port), int(port)+4))

    time.sleep(10)

    cli = clicopy
    cli += ' switch-local lldp-show format local-port no-show-headers '
    lldp_local_ports = run_cli(module, cli).split()
    active_ports = list(set(lldp_local_ports) - set(local_ports))

    if splitter_ports:
        for ports_list in splitter_ports[:]:
            for port in active_ports:
                if int(port) in ports_list:
                    if ports_list in splitter_ports:
                        splitter_ports.remove(ports_list)

    for port_list in splitter_ports:
        first_port = port_list[0]
        for port in port_list:
            if int(port) > len(max_ports):
                continue
            else:
                cli = clicopy
                cli += ' switch-local port-config-modify port %s ' % port
                cli += ' disable '
                output += run_cli(module, cli)
                output += 'port ' + str(port) + '  disabled'
        cli = clicopy
        cli += ' switch-local port-config-modify port %s ' % first_port
        cli += ' speed %s ' % port_speed
        output += run_cli(module, cli)
        output += 'port ' + str(first_port) + ' is now %s ' % port_speed

    return output


def toggle_local(module):
    """
    Method to toggle 40g/100g ports to 10g/25g ports.
    :param module: The Ansible module to fetch input parameters.
    :return: The output messages for assignment.
    """
    output = ''
    ports_40g, ports_100g = [], []
    cli = pn_cli(module)
    clicopy = cli
    cli += ' switch-local lldp-show format local-port no-show-headers '
    local_ports = run_cli(module, cli).split()

    cli = clicopy
    cli += ' switch-local port-config-show format port,speed parsable-delim , '
    max_ports = run_cli(module, cli).split('\n')

    for port_info in max_ports:
        if port_info:
            port_info = port_info.strip().split(',')
            port, speed = port_info[0], port_info[1]
            if '40g' in speed:
                ports_40g.append(port)
            if '100g' in speed:
                ports_100g.append(port)

    if ports_40g:
        output += toggle(module, ports_40g, local_ports, '10g', '40g', max_ports)

    if ports_100g:
        output += toggle(module, ports_100g, local_ports, '25g', '100g', max_ports)

    return output


def assign_inband_ip(module):
    """
    Method to assign in-band ips to switches.
    :param module: The Ansible module to fetch input parameters.
    :return: String describing in-band ip got assigned or not.
    """
    global CHANGED_FLAG
    address = module.params['pn_inband_ip'].split('.')
    static_part = str(address[0]) + '.' + str(address[1]) + '.'
    static_part += str(address[2]) + '.'
    last_octet = str(address[3]).split('/')
    subnet = last_octet[1]

    switches_list = []
    spines = module.params['pn_spine_list']
    leafs = module.params['pn_leaf_list']
    switch = module.params['pn_current_switch']

    if spines:
        switches_list += spines

    if leafs:
        switches_list += leafs

    if switches_list:
        ip_count = switches_list.index(switch) + 1
        ip = static_part + str(ip_count) + '/' + subnet

        # Get existing in-band ip.
        cli = pn_cli(module)
        clicopy = cli
        cli += ' switch-local switch-setup-show format in-band-ip '
        existing_inband_ip = run_cli(module, cli)

        if ip not in existing_inband_ip:
            cli = clicopy
            cli += ' switch-local switch-setup-modify '
            cli += ' in-band-ip ' + ip
            run_cli(module, cli)
            CHANGED_FLAG.append(True)

        return 'Assigned in-band ip ' + ip

    return 'Could not assign in-band ip'


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliusername=dict(required=False, type='str', no_log=True),
            pn_clipassword=dict(required=False, type='str', no_log=True),
            pn_fabric_name=dict(required=True, type='str'),
            pn_fabric_network=dict(required=False, type='str',
                                   choices=['mgmt', 'in-band'], default='mgmt'),
            pn_fabric_control_network=dict(required=False, type='str',
                                           choices=['mgmt', 'in-band'],
                                           default='mgmt'),
            pn_toggle_port_speed=dict(required=False, type='bool', default=True),
            pn_spine_list=dict(required=False, type='list', default=[]),
            pn_leaf_list=dict(required=False, type='list', default=[]),
            pn_inband_ip=dict(required=False, type='str', default='192.16.0.0/24'),
            pn_current_switch=dict(required=False, type='str'),
            pn_static_setup=dict(required=False, type='bool', default=False),
            pn_mgmt_ip=dict(required=False, type='str'),
            pn_mgmt_ip_subnet=dict(required=False, type='str'),
            pn_gateway_ip=dict(required=False, type='str'),
            pn_dns_ip=dict(required=False, type='str'),
            pn_dns_secondary_ip=dict(required=False, type='str'),
            pn_domain_name=dict(required=False, type='str'),
            pn_ntp_server=dict(required=False, type='str'),
            pn_web_api=dict(type='bool', default=True),
            pn_stp=dict(required=False, type='bool', default=True),
            pn_autotrunk=dict(required=False, type='str',
                              choices=['enable', 'disable'], default='disable'),
            pn_autoneg=dict(required=False, type='bool', default=False)
        )
    )

    fabric_name = module.params['pn_fabric_name']
    fabric_network = module.params['pn_fabric_network']
    control_network = module.params['pn_fabric_control_network']
    toggle_flag = module.params['pn_toggle_port_speed']
    current_switch = module.params['pn_current_switch']
    autotrunk = module.params['pn_autotrunk']
    autoneg = module.params['pn_autoneg']
    results = []
    global CHANGED_FLAG

    # Make switch setup static
    if module.params['pn_static_setup']:
        make_switch_setup_static(module)

    # Update switch names to match host names from hosts file
    if 'Updated' in update_switch_names(module, current_switch):
        CHANGED_FLAG.append(True)

    # Create/join fabric
    if 'created' in create_or_join_fabric(module, fabric_name,
                                          fabric_network):
        CHANGED_FLAG.append(True)
        results.append({
            'switch': current_switch,
            'output': u"Created fabric '{}'".format(fabric_name)
        })
    else:
        CHANGED_FLAG.append(True)
        results.append({
            'switch': current_switch,
            'output': u"Joined fabric '{}'".format(fabric_name)
        })

    # Modify auto-neg for T2+ platforms
    if autoneg is True and current_switch in module.params['pn_spine_list']:
        out = modify_auto_neg(module)
        CHANGED_FLAG.append(True)
        results.append({
            'switch': current_switch,
            'output': out
        })

    # Configure fabric control network to either mgmt or in-band
    if 'Success' in configure_control_network(module, control_network):
        CHANGED_FLAG.append(True)
        results.append({
            'switch': current_switch,
            'output': u"Configured fabric control network to '{}'".format(
                control_network)
        })

    # Enable/disable auto-trunk
    if autotrunk:
        modify_auto_trunk(module, autotrunk)
        CHANGED_FLAG.append(True)
        results.append({
            'switch': current_switch,
            'output': u"Auto-trunk {}d".format(autotrunk)
        })

    # Enable web api if flag is True
    if module.params['pn_web_api']:
        enable_web_api(module)

    # Enable STP
    if 'Success' in modify_stp_local(module, 'enable'):
        CHANGED_FLAG.append(True)

    # Enable jumbo flag
    if 'Success' in ports_modify_jumbo(module, 'jumbo'):
        CHANGED_FLAG.append(True)
        results.append({
            'switch': current_switch,
            'output': 'Jumbo enabled in ports'
        })

    # Enable ports
    if enable_ports(module):
        CHANGED_FLAG.append(True)
        results.append({
            'switch': current_switch,
            'output': 'Ports enabled'
        })

    # Toggle 40g/100g ports to 10g/25g
    if toggle_flag:
        if toggle_local(module):
            CHANGED_FLAG.append(True)
            results.append({
                'switch': current_switch,
                'output': 'Toggled 40G/100g ports to 10G/25g '
            })

    # Assign in-band ips.
    out = assign_inband_ip(module)
    results.append({
        'switch': current_switch,
        'output': out
    })

    # Enable STP if flag is True
    if module.params['pn_stp']:
        if 'Success' in modify_stp_local(module, 'enable'):
            CHANGED_FLAG.append(True)
            results.append({
                'switch': current_switch,
                'output': 'STP enabled'
            })

    # Exit the module and return the required JSON
    module.exit_json(
        unreachable=False,
        msg='Fabric creation succeeded',
        summary=results,
        exception='',
        task='Fabric creation',
        failed=False,
        changed=True if True in CHANGED_FLAG else False
    )

if __name__ == '__main__':
    main()
