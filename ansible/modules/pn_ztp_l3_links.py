#!/usr/bin/python
""" PN CLI Layer3 Zero Touch Provisioning (ZTP) """

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
from ansible.module_utils.pn_nvos import *

DOCUMENTATION = """
---
module: pn_ztp_l3_links
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: CLI command to configure ZTP for Layer3 fabric.
description:
    Zero Touch Provisioning (ZTP) allows you to provision new switches in your
    network automatically, without manual intervention. For layer3 fabric,
    it creates vrouters and configures vrouter interfaces (link IPs).
options:
    pn_net_address:
      description:
        - Specify network address to be used in configuring link IPs for layer3.
      required: False
      type: str
    pn_cidr:
      description:
        - Specify CIDR value to be used in configuring link IPs for layer3.
      required: False
      type: str
    pn_supernet:
      description:
        - Specify supernet value to be used in configuring link IPs for layer3.
      required: False
      type: str
    pn_spine_list:
      description:
        - Specify list of Spine hosts.
      required: False
      type: list
    pn_leaf_list:
      description:
        - Specify list of leaf hosts.
      required: False
      type: list
    pn_update_fabric_to_inband:
      description:
        - Flag to indicate if fabric network should be updated to in-band.
      required: False
      default: False
      type: bool
    pn_loopback_ip:
      description:
        - Loopback ip value for vrouters in layer3 fabric.
      required: False
      default: 109.109.109.0/24
      type: str
    pn_bfd:
      description:
        - Flag to indicate if BFD config should be added to vrouter interfaces
        in case of layer3 fabric.
      required: False
      default: False
      type: bool
    pn_bfd_min_rx:
      description:
        - Specify BFD-MIN-RX value required for adding BFD configuration
        to vrouter interfaces.
      required: False
      type: str
    pn_bfd_multiplier:
      description:
        - Specify BFD_MULTIPLIER value required for adding BFD configuration
        to vrouter interfaces.
      required: False
      type: str
    pn_stp:
      description:
        - Flag to enable STP at the end.
      required: False
      default: False
      type: bool
    pn_jumbo_frames:
      description:
        - Flag to assign mtu
      required: False
      default: False
      type: bool
"""

EXAMPLES = """
- name: Zero Touch Provisioning - Layer3 setup
  pn_ztp_l3_links:
    pn_cliusername: "{{ USERNAME }}"
    pn_clipassword: "{{ PASSWORD }}"
    pn_net_address: '192.168.0.1'
    pn_cidr: '24'
    pn_supernet: '30'
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
    Method to execute the cli command on the target node(s) and returns the
    output.
    :param module: The Ansible module to fetch input parameters.
    :param cli: The complete cli string to be executed on the target node(s).
    :return: Output/Error or Success msg depending upon the response from cli.
    """
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)
    results = []
    if out:
        return out

    if err:
        json_msg = {
            'switch': '',
            'output': u'Operation Failed: {}'.format(' '.join(cli))
        }
        results.append(json_msg)
        module.exit_json(
            unreachable=False,
            failed=True,
            exception=err.strip(),
            summary=results,
            task='Configure L3 ZTP',
            msg='L3 ZTP configuration failed',
            changed=False
        )
    else:
        return 'Success'


def modify_stp(module, modify_flag, switch):
    """
    Method to enable/disable STP (Spanning Tree Protocol) on all switches.
    :param module: The Ansible module to fetch input parameters.
    :param modify_flag: Enable/disable flag to set.
    :return: The output of run_cli() method.
    """
    output = ''
    cli = pn_cli(module)
    clicopy = cli

    cli = clicopy
    cli += ' switch %s stp-show format enable ' % switch
    current_state = run_cli(module, cli).split()[1]
    if current_state != 'yes':
        cli = clicopy
        cli += ' switch ' + switch
        cli += ' stp-modify ' + modify_flag
        if 'Success' in run_cli(module, cli):
            CHANGED_FLAG.append(True)

    output += ' %s: STP enabled \n' % switch

    return output


def update_fabric_network_to_inband(module, switch):
    """
    Method to update fabric network type to in-band
    :param module: The Ansible module to fetch input parameters.
    :return: The output of run_cli() method.
    """
    output = ''
    cli = pn_cli(module)
    clicopy = cli

    cli = clicopy
    cli += ' fabric-info format fabric-network '
    fabric_network = run_cli(module, cli).split()[1]
    if fabric_network != 'in-band':
        cli = clicopy
        cli += ' switch ' + switch
        cli += ' fabric-local-modify fabric-network in-band '
        if 'Success' in run_cli(module, cli):
            CHANGED_FLAG.append(True)

    output += ' %s: Updated fabric network to in-band \n' % switch

    return output


def calculate_link_ip_addresses_ipv4(address_str, cidr_str, supernet_str):
    """
    Method to calculate link IPs for layer 3 fabric.
    :param address_str: Host/network address.
    :param cidr_str: Subnet mask.
    :param supernet_str: Supernet mask.
    :return: List of available IP addresses that can be assigned to vrouter
    interfaces for layer 3 fabric.
    """
    # Split address into octets and turn CIDR, supernet mask into int
    address = address_str.split('.')
    cidr = int(cidr_str)
    supernet = int(supernet_str)
    supernet_range = (1 << (32 - supernet)) - 2
    base_addr = int(address[3])

    # Initialize the netmask and calculate based on CIDR mask
    mask = [0, 0, 0, 0]
    for i in range(cidr):
        mask[i / 8] += (1 << (7 - i % 8))

    # Initialize net and binary and netmask with addr to get network
    network = []
    for i in range(4):
        network.append(int(address[i]) & mask[i])

    # Duplicate net into broad array, gather host bits, and generate broadcast
    broadcast = list(network)
    broadcast_range = 32 - cidr
    for i in range(broadcast_range):
        broadcast[3 - i / 8] += (1 << (i % 8))

    last_ip = list(broadcast)
    diff = base_addr % (supernet_range + 2)
    host = base_addr - diff
    count, hostmin, hostmax = 0, 0, 0
    third_octet = network[2]
    available_ips = []
    while third_octet <= last_ip[2]:
        ips_list = []
        while count < last_ip[3]:
            hostmin = host + 1
            hostmax = hostmin + supernet_range - 1
            if supernet == 31:
                while hostmax <= hostmin:
                    ips_list.append(hostmax)
                    hostmax += 1
                host = hostmin + 1
            else:
                while hostmin <= hostmax:
                    ips_list.append(hostmin)
                    hostmin += 1
                host = hostmax + 2

            count = host

        list_index = 0
        ip_address = str(last_ip[0]) + '.' + str(last_ip[1]) + '.'
        ip_address += str(third_octet)
        while list_index < len(ips_list):
            ip = ip_address + '.' + str(ips_list[list_index]) + "/"
            ip += supernet_str
            available_ips.append(ip)
            list_index += 1

        host, count, hostmax, hostmin = 0, 0, 0, 0
        third_octet += 1

    return available_ips


def find_network_v6(address, mask):
    """
    Method to find the network address
    :param address: The address whose network to be found.
    :param mask: Subnet mask.
    :return: The network ip.
    """
    network = []
    for i in range(8):
        network.append(int(address[i], 16) & mask[i])

    return network


def find_broadcast_v6(network, cidr):
    """
    Method to find the broadcast address
    :param network: The network ip whose broadcast ip to be found.
    :param cidr: Subnet mask.
    :return: The broadcast ip.
    """
    broadcast = list(network)
    broadcast_range = 128 - cidr
    for i in range(broadcast_range):
        broadcast[7 - i / 16] += (1 << (i % 16))

    return broadcast


def find_mask_v6(cidr):
    """
    Method to find the subnet mask.
    :param cidr: Subnet mask.
    :return: The subnet mask
    """
    mask = [0, 0, 0, 0, 0, 0, 0, 0]
    for i in range(cidr):
        mask[i / 16] += (1 << (15 - i % 16))

    return mask


def find_network_supernet_v6(broadcast, cidr, supernet):
    """
    Method to find the subnet address
    :param broadcast: The next subnet to be found after the broadcast ip.
    :param cidr: Subnet mask.
    :param supernet: Supernet mask.
    :return: The next subnet after the broadcast ip.
    """
    host_bit = ''
    for j in range(128-supernet):
        host_bit += '0'

    subnet_network_bit = []
    for j in range((supernet/16) + 1):
        subnet_network_bit.append(str(bin(broadcast[j])[2:]).rjust(16, '0'))
    subnet_network_bit = ''.join(subnet_network_bit)

    network_bit = subnet_network_bit[:cidr]

    subnet_bit = subnet_network_bit[cidr:supernet]
    subnet_bit = bin(int(subnet_bit, 2) + 1)[2:].rjust(supernet - cidr, '0')

    final_subnet_binary = network_bit + subnet_bit + host_bit
    final_subnet = []
    temp1 = ''
    for k in range(32):
        temp = final_subnet_binary[(4 * k):(4 * (k+1))]
        temp1 += hex(int(temp, 2))[2:]

        if (k % 4) == 3:
            final_subnet.append(int(temp1, 16))
            temp1 = ''

    return final_subnet


def calculate_link_ip_addresses_ipv6(address_str, cidr_str, supernet_str, ip_count):
    """
    Generator to calculate link IPs for layer 3 fabric.
    :param address_str: Host/network address.
    :param cidr_str: Subnet mask.
    :param supernet_str: Supernet mask.
    :ip_count: No. of ips required per build.
    :return: List of available IP addresses that can be assigned to vrouter
    interfaces for layer 3 fabric.
    """
    if '::' in address_str:
        add_str = ''
        count = (address_str.count(':'))
        if address_str[-1] == ':':
            count -= 2
            while count < 7:
                add_str += ':0'
                count += 1
        else:
            while count < 8:
                add_str += ':0'
                count += 1
            add_str += ':'

        address_str = address_str.replace('::', add_str)

    address = address_str.split(':')
    cidr = int(cidr_str)
    supernet = int(supernet_str)

    mask_cidr = find_mask_v6(cidr)
    network = find_network_v6(address, mask_cidr)
    broadcast = find_broadcast_v6(network, cidr)

    mask_supernet = find_mask_v6(supernet)
    network_hex = []
    for i in range(8):
        network_hex.append(hex(network[i])[2:])
    network_supernet = find_network_v6(network_hex, mask_supernet)
    broadcast_supernet = find_broadcast_v6(network_supernet, supernet)

    initial_ip = network_supernet[7]
    ip_checking = list(network_supernet)
    while not(initial_ip >= broadcast[7] and ip_checking[:7] == broadcast[:7]):
        initial_ip = network_supernet[7]
        ips_list = []
        no_of_ip = 0
        while initial_ip <= broadcast_supernet[7] and no_of_ip < ip_count:
            ip = list(network_supernet)
            ip[7] = initial_ip

            for i in range(0, 8):
                ip[i] = hex(ip[i])[2:]

            ip = ':'.join(ip)
            ip += '/' + str(supernet)
            ips_list.append(ip)
            initial_ip += 1
            no_of_ip += 1
            ip_checking = list(broadcast_supernet)
        initial_ip = broadcast_supernet[7]
        network_supernet = find_network_supernet_v6(broadcast_supernet, cidr, supernet)
        broadcast_supernet = find_broadcast_v6(network_supernet, supernet)

        yield ips_list


def create_vrouter(module, switch, vnet_name):
    """
    Method to create vrouter on a switch.
    :param module: The Ansible module to fetch input parameters.
    :param switch: The switch name on which vrouter will be created.
    :param vnet_name: The name of the vnet for vrouter creation.
    :return: String describing if vrouter got created or if it already exists.
    """
    global CHANGED_FLAG
    vrouter_name = switch + '-vrouter'
    cli = pn_cli(module)
    cli += ' switch ' + switch
    clicopy = cli

    # Check if vrouter already exists.
    cli += ' vrouter-show format name no-show-headers '
    existing_vrouter_names = run_cli(module, cli).split()

    # If vrouter doesn't exists then create it.
    if vrouter_name not in existing_vrouter_names:
        cli = clicopy
        cli += ' vrouter-create name %s vnet %s ' % (vrouter_name, vnet_name)
        cli += ' router-type hardware '
        run_cli(module, cli)
        CHANGED_FLAG.append(True)

    return ' %s: Created vrouter with name %s \n' % (switch, vrouter_name)


def create_interface(module, switch, ip_ipv4, ip_ipv6, port, addr_type):
    """
    Method to create vrouter interface and assign IP to it.
    :param module: The Ansible module to fetch input parameters.
    :param switch: The switch name on which vrouter will be created.
    :param ip: IP address to be assigned to vrouter interfaces.
    :param port: l3-port for the interface.
    :return: The output string informing details of vrouter created and
    interface added or if vrouter already exists.
    """
    output = ''
    global CHANGED_FLAG
    cli = pn_cli(module)
    clicopy = cli
    cli += ' vrouter-show location %s format name no-show-headers ' % switch
    vrouter_name = run_cli(module, cli).split()[0]

    if addr_type == 'ipv4':
        ip = ip_ipv4
    elif addr_type == 'ipv6':
        ip = ip_ipv6
    elif addr_type == 'ipv4_ipv6':
        ip = ip_ipv4
        ip2 = ip_ipv6

    cli = clicopy
    cli += ' vrouter-interface-show l3-port %s ip %s ' % (port, ip)
    cli += ' format switch no-show-headers '
    existing_vrouter = run_cli(module, cli).split()
    existing_vrouter = list(set(existing_vrouter))

    if vrouter_name not in existing_vrouter:
        # Add vrouter interface.
        cli = clicopy
        cli += ' vrouter-interface-add vrouter-name ' + vrouter_name
        cli += ' ip ' + ip
        if addr_type == 'ipv4_ipv6':
            cli += ' ip2 ' + ip2
        cli += ' l3-port ' + port
        if module.params['pn_jumbo_frames'] == True:
            cli += ' mtu 9216'
        if module.params['pn_if_nat_realm']:
            cli += ' if-nat-realm ' + module.params['pn_if_nat_realm']
        run_cli(module, cli)
        # Add BFD config to vrouter interface.
        if module.params['pn_bfd']:
            cli = clicopy
            cli += ' vrouter-interface-show vrouter-name ' + vrouter_name
            cli += ' l3-port %s format nic no-show-headers ' % port
            nic = run_cli(module, cli).split()[1]

            cli = clicopy
            cli += ' vrouter-interface-config-add '
            cli += ' vrouter-name %s nic %s ' % (vrouter_name, nic)
            cli += ' bfd-min-rx ' + module.params['pn_bfd_min_rx']
            cli += ' bfd-multiplier ' + module.params['pn_bfd_multiplier']
            run_cli(module, cli)

        CHANGED_FLAG.append(True)

    output += ' %s: Added vrouter interface with ip %s' % (
        switch, ip
    )
    if addr_type == 'ipv4_ipv6':
        output += ' ip2 ' + ip2
    output += ' on %s \n' % vrouter_name
    if module.params['pn_bfd']:
        output += ' %s: Added BFD configuration to %s \n' % (switch,
                                                             vrouter_name)

    return output


def modify_auto_trunk_setting(module, switch, flag):
    """
    Method to enable/disable auto trunk setting of a switch.
    :param module: The Ansible module to fetch input parameters.
    :param switch: Name of the local switch.
    :param flag: Enable/disable flag for the cli command.
    :return: The output of run_cli() method.
    """
    cli = pn_cli(module)
    if flag.lower() == 'enable':
        cli += ' switch %s system-settings-modify auto-trunk ' % switch
        return run_cli(module, cli)
    elif flag.lower() == 'disable':
        cli += ' switch %s system-settings-modify no-auto-trunk ' % switch
        return run_cli(module, cli)


def delete_trunk(module, switch, switch_port, peer_switch):
    """
    Method to delete a conflicting trunk on a switch.
    :param module: The Ansible module to fetch input parameters.
    :param switch: Name of the local switch.
    :param switch_port: The l3-port which is part of conflicting trunk for l3.
    :param peer_switch: Name of the peer switch.
    :return: String describing if trunk got deleted or not.
    """
    cli = pn_cli(module)
    clicopy = cli

    cli += ' switch %s port-show port %s hostname %s ' % (switch, switch_port,
                                                          peer_switch)
    cli += ' format trunk no-show-headers '
    trunk = run_cli(module, cli).split()
    trunk = list(set(trunk))
    if 'Success' not in trunk and len(trunk) > 0:
        cli = clicopy
        cli += ' switch %s trunk-delete name %s ' % (switch, trunk[0])
        if 'Success' in run_cli(module, cli):
            CHANGED_FLAG.append(True)
            return ' %s: Deleted %s trunk successfully \n' % (switch, trunk[0])


def assign_loopback_ip(module, loopback_address):
    """
    Method to add loopback interface to vrouters.
    :param module: The Ansible module to fetch input parameters.
    :param loopback_address: The loopback ip to be assigned.
    :return: String describing if loopback ips got assigned or not.
    """
    global CHANGED_FLAG
    output = ''
    address = loopback_address.split('.')
    static_part = str(address[0]) + '.' + str(address[1]) + '.'
    static_part += str(address[2]) + '.'

    cli = pn_cli(module)
    clicopy = cli
    switch_list = module.params['pn_spine_list'] + module.params['pn_leaf_list']

    vrouter_count = int(address[3].split('/')[0])
    for switch in switch_list:
        vrouter = switch + '-vrouter'
        ip = static_part + str(vrouter_count)

        cli = clicopy
        cli += ' vrouter-loopback-interface-show ip ' + ip
        cli += ' format switch no-show-headers '
        existing_vrouter = run_cli(module, cli).split()

        if vrouter not in existing_vrouter:
            cli = clicopy
            cli += ' vrouter-loopback-interface-add vrouter-name '
            cli += vrouter
            cli += ' ip ' + ip
            run_cli(module, cli)
            CHANGED_FLAG.append(True)

        output += ' %s: Added loopback ip %s to %s \n' % (switch, ip, vrouter)
        vrouter_count += 1

    return output


def finding_initial_ip(module, current_switch, leaf_list):
    """
    Method to find the intial ip of the ipv4 addressing scheme.
    :param module: The Ansible module to fetch input parameters.
    :param available_ips_ipv4: The list of all possibe ipv4 addresses.
    :param current_switch: The current switch in which the execution is
                           taking place.
    :param leaf_list: The list of all leafs.
    :return: String describing output of configuration.
    """
    spine_list = list(module.params['pn_spine_list'])
    spine_list = [x.strip() for x in spine_list]
    spines = ','.join(spine_list)
    count_output = 0

    cli = pn_cli(module)
    clicopy = cli

    for leaf in leaf_list:
        if leaf.strip() == current_switch.strip():
            break
        cli = clicopy
        cli += " switch %s port-show hostname %s count-output | grep Count" %  (leaf, spines)
        count_output += int(run_cli(module, cli).split(':')[1].strip())

    return count_output


def auto_configure_link_ips(module):
    """
    Method to auto configure link IPs for layer3 fabric.
    :param module: The Ansible module to fetch input parameters.
    :return: String describing output of configuration.
    """
    spine_list = module.params['pn_spine_list']
    leaf_list = module.params['pn_leaf_list']
    addr_type = module.params['pn_addr_type']
    supernet_ipv4 = module.params['pn_supernet_ipv4']
    supernet_ipv6 = module.params['pn_supernet_ipv6']
    current_switch = module.params['pn_current_switch']
    output = ''

    cli = pn_cli(module)
    clicopy = cli

    if current_switch in leaf_list:
        # Disable auto trunk on all switches.
        modify_auto_trunk_setting(module, current_switch, 'disable')
        for spine in spine_list:
            # Disable auto trunk.
            modify_auto_trunk_setting(module, spine, 'disable')

        # Get the list of available link ips to assign.
        count_output = finding_initial_ip(module, current_switch, leaf_list)
        if addr_type == 'ipv4' or addr_type == 'ipv4_ipv6':
            count = 0
            available_ips_ipv4 = calculate_link_ip_addresses_ipv4(module.params['pn_net_address_ipv4'],
                                                                  module.params['pn_cidr_ipv4'],
                                                                  supernet_ipv4)

            diff = 32 - int(supernet_ipv4)
            count = (1 << diff) - 4
            count = (count + 2) if count > 0 else 2
            count = count * count_output
            available_ips_ipv4 = available_ips_ipv4[count:]

        # Get the list of available link ips to assign.
        if addr_type == 'ipv6' or addr_type == 'ipv4_ipv6':
            get_count = 2 if supernet_ipv6 == '127' else 3
            available_ips_ipv6 = calculate_link_ip_addresses_ipv6(module.params['pn_net_address_ipv6'],
                                                                  module.params['pn_cidr_ipv6'],
                                                                  supernet_ipv6, get_count)
            for i in range(count_output):
                available_ips_ipv6.next()

        for spine in spine_list:
            cli = clicopy
            cli += ' switch %s port-show hostname %s ' % (current_switch, spine)
            cli += ' format port no-show-headers '
            leaf_port = run_cli(module, cli).split()
            leaf_port = list(set(leaf_port))

            if 'Success' in leaf_port:
                continue

            while len(leaf_port) > 0:
                ip_ipv6 = ''
                ip_ipv4 = ''
                if addr_type == 'ipv6' or addr_type == 'ipv4_ipv6':
                    try:
                        ip_list = available_ips_ipv6.next()
                    except:
                        msg = 'Error: ipv6 range exhausted'
                        results = {
                            'switch': '',
                            'output': msg
                        }
                        module.exit_json(
                            unreachable=False,
                            failed=True,
                            exception=msg,
                            summary=results,
                            task='L3 ZTP',
                            msg='L3 ZTP failed',
                            changed=False
                        )
                    ip_ipv6 = (ip_list[0] if supernet_ipv6 == '127' else ip_list[1])

                lport = leaf_port[0]

                cli = clicopy
                cli += ' switch %s port-show port %s ' % (current_switch, lport)
                cli += ' format rport no-show-headers '
                rport = run_cli(module, cli).split()
                rport = list(set(rport))
                rport = rport[0]

                if addr_type == 'ipv4' or addr_type == 'ipv4_ipv6':
                    ip_ipv4 = available_ips_ipv4[0]
                    available_ips_ipv4.remove(ip_ipv4)

                delete_trunk(module, spine, rport, current_switch)
                output += create_interface(module, spine, ip_ipv4, ip_ipv6, rport, addr_type)

                leaf_port.remove(lport)
                if addr_type == 'ipv6' or addr_type == 'ipv4_ipv6':
                    ip_ipv6 = (ip_list[1] if supernet_ipv6 == '127' else ip_list[2])

                if addr_type == 'ipv4' or addr_type == 'ipv4_ipv6':
                    ip_ipv4 = available_ips_ipv4[0]
                    available_ips_ipv4.remove(ip_ipv4)
                    ip_count = 0
                    diff = 32 - int(supernet_ipv4)
                    count = (1 << diff) - 4
                    if count > 0:
                        while ip_count < count:
                            available_ips_ipv4.pop(0)
                            ip_count += 1

                delete_trunk(module, current_switch, lport, spine)
                output += create_interface(module, current_switch, ip_ipv4, ip_ipv6, lport, addr_type)

        # Enable auto trunk on all switches.
        modify_auto_trunk_setting(module, current_switch, 'enable')
        for spine in spine_list:
            # Enable auto trunk.
            modify_auto_trunk_setting(module, spine, 'enable')

    return output


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_current_switch=dict(required=False, type='str'),
            pn_addr_type=dict(required=False, type='str',
                              choices=['ipv4', 'ipv6', 'ipv4_ipv6'], default='ipv4'),
            pn_net_address_ipv4=dict(required=False, type='str'),
            pn_net_address_ipv6=dict(required=False, type='str'),
            pn_cidr_ipv4=dict(required=False, type='str'),
            pn_cidr_ipv6=dict(required=False, type='str'),
            pn_supernet_ipv4=dict(required=False, type='str'),
            pn_supernet_ipv6=dict(required=False, type='str'),
            pn_spine_list=dict(required=False, type='list'),
            pn_leaf_list=dict(required=False, type='list'),
            pn_if_nat_realm=dict(required=False, type='str',
                                 choices=['internal', 'external'], default='internal'),
            pn_update_fabric_to_inband=dict(required=False, type='bool',
                                            default=False),
            pn_loopback_ip=dict(required=False, type='str',
                                default='109.109.109.1/24'),
            pn_bfd=dict(required=False, type='bool', default=False),
            pn_bfd_min_rx=dict(required=False, type='str'),
            pn_bfd_multiplier=dict(required=False, type='str'),
            pn_stp=dict(required=False, type='bool', default=False),
            pn_jumbo_frames=dict(required=False, type='bool', default=False),
        )
    )

    global CHANGED_FLAG

    # L3 setup (link ips)
    message = auto_configure_link_ips(module)

    # Update fabric network to in-band if flag is True
    if module.params['pn_update_fabric_to_inband']:
        message += update_fabric_network_to_inband(module, module.params['pn_current_switch'])

    # Enable STP if flag is True
    if module.params['pn_stp']:
        message += modify_stp(module, 'enable', module.params['pn_current_switch'])

    message_string = message
    results = []
    switch_list = module.params['pn_spine_list'] + module.params['pn_leaf_list']

    for switch in switch_list:
        replace_string = switch + ': '
        for line in message_string.splitlines():
            if replace_string in line:
                json_msg = {
                    'switch': switch,
                    'output': (line.replace(replace_string, '')).strip()
                }
                results.append(json_msg)

    # Exit the module and return the required JSON.
    module.exit_json(
        unreachable=False,
        msg='L3 ZTP configuration succeeded',
        summary=results,
        exception='',
        failed=False,
        changed=True if True in CHANGED_FLAG else False,
        task='Configure L3 ZTP'
    )

if __name__ == '__main__':
    main()

