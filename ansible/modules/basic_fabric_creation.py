#!/usr/bin/python
""" PN Basic Fabric Creation """

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
from ansible.module_utils.pn_nvos import pn_cli

DOCUMENTATION = """
---
module: basic_fabric_creation
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
    pn_switch_list:
      description:
        - Specify list of switches.
      required: False
      type: list
    pn_fabric_name:
      description:
        - Specify name of the fabric.
      required: False
      type: str
    pn_inband_ip:
      description:
        - Inband ips to be assigned to switches starting with this value.
      required: False
      default: 172.16.0.0/24.
      type: str
    pn_switch:
      description:
        - Name of the switch on which this task is currently getting executed.
      required: False
      type: str
    pn_toggle_port_speed:
      description:
        - Flag to indicate if port speed should be toggled for better topology visibility.
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
    basic_fabric_creation:
      pn_cliusername: "{{ ansible_user }}"
      pn_clipassword: "{{ ansible_ssh_pass }}"
      pn_switch: "{{ inventory_hostname }}"
      pn_switch_list: "{{ groups['switch'] }}"
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


def run_cli(module, cli):
    """
    Execute the cli command on the target node(s) and returns the output.
    :param module: The Ansible module to fetch input parameters.
    :param cli: The complete cli string to be executed on the target node(s).
    :return: Output or Error msg depending upon the response from cli else None.
    """
    results = []
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)

    if out:
        return out
    if err:
        json_msg = {
            'switch': module.params['pn_switch'],
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
        return None


def assign_inband_ip(module):
    """
    Method to assign in-band ips to switches.
    :param module: The Ansible module to fetch input parameters.
    :return: String describing in-band ip got assigned or not.
    """
    global CHANGED_FLAG
    output = ''
    address = module.params['pn_inband_ip'].split('.')
    static_part = str(address[0]) + '.' + str(address[1]) + '.'
    static_part += str(address[2]) + '.'
    last_octet = str(address[3]).split('/')
    subnet = last_octet[1]

    switches_list = module.params['pn_switch_list']
    switch = module.params['pn_switch']

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
            cli += ' in-band-ip %s ' % ip
            run_cli(module, cli)
            CHANGED_FLAG.append(True)
            output += 'Assigned in-band ip %s' % ip

        return output

    return 'Could not assign in-band ip'


def toggle(module, curr_switch, toggle_ports, toggle_speed, port_speed, splitter_ports, quad_ports):
    """
    Method to toggle ports for topology discovery
    :param module: The Ansible module to fetch input parameters.
    :return: The output messages for assignment.
    :param curr_switch on which we run toggle.
    :param toggle_ports to be toggled.
    :param toggle_speed to which ports to be toggled.
    :param splitter_ports are splitter ports
    """
    output = ''
    cli = pn_cli(module)
    clicopy = cli

    for speed in toggle_speed:
        if int(port_speed.strip('g'))/int(speed.strip('g')) >= 4:
            is_splittable = True
        else:
            is_splittable = False
        cli = clicopy
        cli += 'switch %s lldp-show format local-port ' % curr_switch
        cli += 'parsable-delim ,'
        local_ports = run_cli(module, cli).split()

        _undiscovered_ports = sorted(list(set(toggle_ports) - set(local_ports)),
                                     key=lambda x: int(x))
        non_splittable_ports = []
        undiscovered_ports = []

        for _port in _undiscovered_ports:
            if splitter_ports.get(_port, 0) == 1:
                undiscovered_ports.append("%s-%s" % (_port, int(_port)+3))
            elif splitter_ports.get(_port, 0) == 0:
                undiscovered_ports.append(_port)
            else:
                # Skip intermediate splitter ports
                continue
            if not is_splittable:
                non_splittable_ports.append(_port)
        undiscovered_ports = ",".join(undiscovered_ports)

        if not undiscovered_ports:
            continue

        cli = clicopy
        cli += 'switch %s port-config-modify port %s ' % (curr_switch, undiscovered_ports)
        cli += 'disable'
        run_cli(module, cli)

        if non_splittable_ports:
            non_splittable_ports = ",".join(non_splittable_ports)
            cli = clicopy
            cli += 'switch %s port-config-modify ' % curr_switch
            cli += 'port %s ' % non_splittable_ports
            cli += 'speed %s enable' % speed
            run_cli(module, cli)
        else:
            cli = clicopy
            cli += 'switch %s port-config-modify ' % curr_switch
            cli += 'port %s ' % undiscovered_ports
            cli += 'speed %s enable' % speed
            run_cli(module, cli)

        time.sleep(10)

    # Revert undiscovered ports back to their original speed
    cli = clicopy
    cli += 'switch %s lldp-show format local-port ' % curr_switch
    cli += 'parsable-delim ,'
    local_ports = run_cli(module, cli).split()
    _undiscovered_ports = sorted(list(set(toggle_ports) - set(local_ports)),
                                 key=lambda x: int(x))
    disable_ports = []
    undiscovered_ports = []
    for _port in _undiscovered_ports:
        if _port in quad_ports:
            disable_ports.append(str(_port))
            # dont add to undiscovered ports
        elif splitter_ports.get(_port, 0) == 1:
            disable_ports.append("%s-%s" % (_port, int(_port)+3))
            undiscovered_ports.append(_port)
        elif splitter_ports.get(_port, 0) == 0:
            disable_ports.append(str(_port))
            undiscovered_ports.append(_port)
        else:
            # Skip intermediate splitter ports
            pass

    disable_ports = ",".join(disable_ports)
    if disable_ports:
        cli = clicopy
        cli += 'switch %s port-config-modify port %s disable' % (curr_switch, disable_ports)
        run_cli(module, cli)

    undiscovered_ports = ",".join(undiscovered_ports)
    if not undiscovered_ports:
        return

    cli = clicopy
    cli += 'switch %s port-config-modify ' % curr_switch
    cli += 'port %s ' % undiscovered_ports
    cli += 'speed %s enable' % port_speed
    run_cli(module, cli)
    output += 'Toggle completed successfully '

    return output


def toggle_ports(module, curr_switch):
    """
    Method to discover the toggle ports.
    :param module: The Ansible module to fetch input parameters.
    :param curr_switch on which toggle discovery happens.
    """
    cli = pn_cli(module)
    clicopy = cli
    g_toggle_ports = {
        '25g': {'ports': [], 'speeds': ['10g']},
        '40g': {'ports': [], 'speeds': ['10g']},
        '100g': {'ports': [], 'speeds': ['10g', '25g', '40g']}
    }
    ports_25g = []
    ports_40g = []
    ports_100g = []

    cli += 'switch %s port-config-show format port,speed ' % curr_switch
    cli += 'parsable-delim ,'
    max_ports = run_cli(module, cli).split()

    all_next_ports = []
    for port_info in max_ports:
        if port_info:
            port, speed = port_info.strip().split(',')
            all_next_ports.append(str(int(port)+1))
            if g_toggle_ports.get(speed, None):
                g_toggle_ports[speed]['ports'].append(port)

    # Get info on splitter ports
    g_splitter_ports = {}
    all_next_ports = ','.join(all_next_ports)
    cli = clicopy
    cli += 'switch %s port-show port %s format ' % (curr_switch, all_next_ports)
    cli += 'port,bezel-port parsable-delim ,'
    splitter_info = run_cli(module, cli).split()

    for sinfo in splitter_info:
        if not sinfo:
            break
        _port, _sinfo = sinfo.split(',')
        _port = int(_port)
        if '.2' in _sinfo:
            for i in range(4):
                g_splitter_ports[str(_port-1 + i)] = 1 + i

    # Get info on Quad Ports
    g_quad_ports = {'25g': []}
    cli = clicopy
    cli += 'switch %s switch-info-show format model, layout horizontal ' % curr_switch
    cli += 'parsable-delim ,'
    model_info = run_cli(module, cli).split()

    for modinfo in model_info:
        if not modinfo:
            break
        model = modinfo
        if model == "ACCTON-AS7316-54X" and g_toggle_ports.get('25g', None):
            for _port in g_toggle_ports['25g']['ports']:
                if _port not in g_splitter_ports:
                    g_quad_ports['25g'].append(_port)

    for port_speed, port_info in g_toggle_ports.iteritems():
        if port_info['ports']:
            toggle(module, curr_switch, port_info['ports'], port_info['speeds'], port_speed,
                   g_splitter_ports, g_quad_ports.get(port_speed, []))


def enable_ports(module):
    """
    Method to enable all ports of a switch.
    :param module: The Ansible module to fetch input parameters.
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

        if len(out_40g) > 0 and out_40g != None:
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
                run_cli(module, cli)


def modify_stp(module, modify_flag):
    """
    Method to enable/disable STP (Spanning Tree Protocol) on a switch.
    :param module: The Ansible module to fetch input parameters.
    :param modify_flag: Enable/disable flag to set.
    """
    cli = pn_cli(module)
    cli += ' switch-local stp-show format enable '
    current_state = run_cli(module, cli).split()[1]

    state = 'yes' if modify_flag == 'enable' else 'no'

    if current_state == state:
        cli = pn_cli(module)
        cli += ' switch-local stp-modify %s ' % modify_flag
        run_cli(module, cli)


def enable_web_api(module):
    """
    Enable web api on a switch.
    :param module: The Ansible module to fetch input parameters.
    """
    cli = pn_cli(module)
    cli += ' admin-service-modify web if mgmt '
    run_cli(module, cli)


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
    if cli_out is None:
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


def configure_control_network(module):
    """
    Configure the fabric control network to mgmt.
    :param module: The Ansible module to fetch input parameters.
    """
    network = 'mgmt'
    cli = pn_cli(module)
    cli += ' fabric-info format control-network '
    current_control_network = run_cli(module, cli).split()[1]

    if current_control_network != network:
        cli = pn_cli(module)
        cli += ' fabric-local-modify control-network %s ' % network
        run_cli(module, cli)


def make_switch_setup_static(module):
    """
    Method to assign static values to different switch setup parameters.
    :param module: The Ansible module to fetch input parameters.
    """
    dns_ip = module.params['pn_dns_ip']
    dns_secondary_ip = module.params['pn_dns_secondary_ip']
    domain_name = module.params['pn_domain_name']
    ntp_server = module.params['pn_ntp_server']

    cli = pn_cli(module)
    cli += ' switch-setup-modify '

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


def create_fabric(module, fabric_name):
    """
    Create a fabric
    :param module: The Ansible module to fetch input parameters.
    :param fabric_name: Name of the fabric to create.
    :return: 'Created fabric fabric_name'
    """
    cli = pn_cli(module)
    cli += ' fabric-create name %s fabric-network mgmt ' % fabric_name
    run_cli(module, cli)
    CHANGED_FLAG.append(True)
    return 'Created fabric {}'.format(fabric_name)


def join_fabric(module, fabric_name):
    """
    Join existing fabric
    :param module: The Ansible module to fetch input parameters.
    :param fabric_name: Name of the fabric to join to.
    :return: 'Joined fabric fabric_name'
    """
    cli = pn_cli(module)
    cli += ' fabric-join name %s ' % fabric_name
    run_cli(module, cli)
    CHANGED_FLAG.append(True)
    return 'Joined fabric {}'.format(fabric_name)


def modify_auto_neg(module):
    """
    Module to enable/disable auto-neg for T2+ platforms.
    :param module: The Ansible module to fetch input parameters.
    """
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
    cli += ' switch-local port-config-modify port ' + ','.join(idle_ports)
    cli += ' autoneg '
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
    cli += ' switch-local port-config-modify port ' + ','.join(idle_ports)
    cli += ' no-autoneg '
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


def is_switches_connected(module):
    """
    Check if switches are physically connected to each other.
    :param module: The Ansible module to fetch input parameters.
    :return: True if connected else False.
    """
    cli = pn_cli(module)
    cli += ' lldp-show format switch,sys-name parsable-delim , '
    sys_names = run_cli(module, cli)

    if sys_names is not None:
        switch1 = module.params['pn_switch_list'][0]
        switch2 = module.params['pn_switch_list'][1]

        sys_names = list(set(sys_names.split()))
        for cluster in sys_names:
            if switch1 in cluster and switch2 in cluster:
                return True

    return False


def configure_fabric(module):
    """
    Create/join fabric.
    :param module: The Ansible module to fetch input parameters.
    :return: String describing if fabric got created/joined/already configured.
    """
    switch_list = module.params['pn_switch_list']
    switch = module.params['pn_switch']
    fabric_name = module.params['pn_fabric_name']

    cli = pn_cli(module)
    cli += ' fabric-info format name no-show-headers '
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)

    # Above fabric-info cli command will throw an error, if switch is not part
    # of any fabric. So if err, we need to create/join the fabric.
    if err:
        if len(switch_list) == 2:
            if not is_switches_connected(module):
                msg = 'Error: Switches are not connected to each other'
                results = {
                    'switch': switch,
                    'output': msg
                }
                module.exit_json(
                    unreachable=False,
                    failed=True,
                    exception=msg,
                    summary=results,
                    task='Fabric creation',
                    msg='Fabric creation failed',
                    changed=False
                )

            new_fabric = False
            cli = pn_cli(module)
            cli += ' fabric-show format name no-show-headers '
            existing_fabrics = run_cli(module, cli)

            if existing_fabrics is not None:
                existing_fabrics = existing_fabrics.split()
                if fabric_name not in existing_fabrics:
                    new_fabric = True

            if new_fabric or existing_fabrics is None:
                output = create_fabric(module, fabric_name)
            else:
                output = join_fabric(module, fabric_name)
        else:
            output = create_fabric(module, fabric_name)
    else:
        return 'Fabric already configured'

    return output


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(argument_spec=dict(
        pn_switch_list=dict(required=False, type='list', default=[]),
        pn_fabric_name=dict(required=True, type='str'),
        pn_inband_ip=dict(required=False, type='str', default='172.16.0.0/24'),
        pn_switch=dict(required=False, type='str'),
        pn_toggle_port_speed=dict(required=False, type='bool', default=True),
        pn_dns_ip=dict(required=False, type='str', default=''),
        pn_dns_secondary_ip=dict(required=False, type='str', default=''),
        pn_domain_name=dict(required=False, type='str', default=''),
        pn_ntp_server=dict(required=False, type='str', default=''),
        pn_autotrunk=dict(required=False, type='str',
                          choices=['enable', 'disable'], default='disable'),
        pn_autoneg=dict(required=False, type='bool', default=False), )
    )

    global CHANGED_FLAG
    results = []
    switch = module.params['pn_switch']
    autoneg = module.params['pn_autoneg']
    autotrunk = module.params['pn_autotrunk']

    # Create/join fabric
    out = configure_fabric(module)
    results.append({
        'switch': switch,
        'output': out
    })

    # Determine 'msg' field of JSON that will be returned at the end
    msg = out if 'already configured' in out else 'Fabric creation succeeded'

    # Modify auto-neg for T2+ platforms
    if autoneg is True:
        out = modify_auto_neg(module)
        CHANGED_FLAG.append(True)
        results.append({
            'switch': switch,
            'output': out
        })

    # Configure fabric control network to mgmt
    configure_control_network(module)

    # Enable/disable auto-trunk
    if autotrunk:
        modify_auto_trunk(module, autotrunk)
        CHANGED_FLAG.append(True)
        results.append({
            'switch': switch,
            'output': u"Auto-trunk {}d".format(autotrunk)
        })

    # Update switch setup values
    make_switch_setup_static(module)

    # Enable jumbo flag
    if ports_modify_jumbo(module, 'jumbo') is None:
        CHANGED_FLAG.append(True)
        results.append({
            'switch': switch,
            'output': 'Jumbo enabled in ports'
        })


    # Enable web api
    enable_web_api(module)

    # Disable STP
    modify_stp(module, 'disable')

    # Enable all ports
    enable_ports(module)

    # Convert port speeds for better topology visibility
    if module.params['pn_toggle_port_speed']:
        if toggle_ports(module, module.params['pn_switch']):
            results.append({
                'switch': switch,
                'output': 'Toggled 40G ports to 10G'
            })

    # Assign in-band ips.
    out = assign_inband_ip(module)
    if out:
        results.append({
            'switch': switch,
            'output': out
        })

    # Enable STP
    modify_stp(module, 'enable')

    # Exit the module and return the required JSON
    module.exit_json(
        unreachable=False,
        msg=msg,
        summary=results,
        exception='',
        task='Fabric creation',
        failed=False,
        changed=True if True in CHANGED_FLAG else False
    )

if __name__ == '__main__':
    main()
