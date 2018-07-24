#!/usr/bin/python
""" PN CLI EBGP """

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
module: pn_ztp_ebgp
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: Module to configure eBGP/OSPF.
description: It performs following steps:
    EBGP:
      - Assigning bgp_as
      - Configuring bgp_redistribute
      - Configuring bgp_maxpath
      - Assign ebgp_neighbor
      - Assign router_id
      - Create leaf_cluster
      - Add iBGP neighbor for clustered leaf
options:
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
    pn_ebgp_cidr_ipv4:
      description:
        - Specify CIDR value to be used in configuring IPv4 address.
      required: False
      type: str
    pn_ebgp_subnet_ipv4:
      description:
        - Specify subnet value to be used in configuring IPv4 address.
      required: False
      type: str
    pn_cidr_ipv6:
      description:
        - Specify CIDR value to be used in configuring IPv6 address.
      required: False
      type: str
    pn_subnet_ipv6:
      description:
        - Specify subnet value to be used in configuring IPv6 address.
      required: False
      type: str
    pn_bgp_redistribute:
      description:
        - Specify bgp_redistribute value to be added to vrouter.
      required: False
      type: str
      choices: ['none', 'static', 'connected', 'rip', 'ospf']
      default: 'connected'
    pn_bgp_maxpath:
      description:
        - Specify bgp_maxpath value to be added to vrouter.
      required: False
      type: str
      default: '16'
    pn_bgp_as_range:
      description:
        - Specify bgp_as_range value to be added to vrouter.
      required: False
      type: str
      default: '65000'
    pn_routing_protocol:
      description:
        - Specify which routing protocol to specify.
      required: False
      type: str
      choices: ['ebgp']
    pn_ibgp_ipv4_range:
      description:
        - Specify ip range for ibgp interface.
      required: False
      type: str
      default: '75.75.75.0/30'
    pn_ibgp_vlan:
      description:
        - Specify vlan for ibgp interface.
      required: False
      type: str
      default: '4040'
    pn_bfd:
      description:
        - Specify bfd flag for the ebgp neighbor.
      required: False
      type: bool
      default: False
    pn_jumbo_frames:
      description:
        - Flag to assign mtu
      required: False
      default: False
      type: bool
"""

EXAMPLES = """
- name: Configure eBGP
  pn_ztp_ebgp:
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
            exception='',
            summary=results,
            task='Configure eBGP',
            stderr=err.strip(),
            msg='eBGP configuration failed',
            changed=False
        )
    else:
        return 'Success'


def find_bgp_as_dict(module):
    """
    Method to find bgp-as for all switches and store it in a dictionary.
    :param module: The Ansible module to fetch input parameters.
    :return: Dictionary containing switch: bgp_as key value pairs.
    """
    leaf_list = module.params['pn_leaf_list']
    bgp_as = int(module.params['pn_bgp_as_range'])
    cluster_leaf_list = []
    cli = pn_cli(module)
    clicopy = cli
    dict_bgp_as = {}

    for spine in module.params['pn_spine_list']:
        dict_bgp_as[spine] = str(bgp_as)

    cli += ' cluster-show format name no-show-headers'
    cluster_list = run_cli(module, cli).split()

    if 'Success' not in cluster_list:
        for cluster in cluster_list:
            cli = clicopy
            cli += ' cluster-show name %s' % cluster
            cli += ' format cluster-node-1,cluster-node-2 no-show-headers'
            cluster_nodes = run_cli(module, cli).split()

            if cluster_nodes[0] in leaf_list and cluster_nodes[1] in leaf_list:
                bgp_as += 1
                dict_bgp_as[cluster_nodes[0]] = str(bgp_as)
                dict_bgp_as[cluster_nodes[1]] = str(bgp_as)
                cluster_leaf_list.append(cluster_nodes[0])
                cluster_leaf_list.append(cluster_nodes[1])

    non_clustered_leaf_list = list(set(leaf_list) - set(cluster_leaf_list))
    for leaf in non_clustered_leaf_list:
        bgp_as += 1
        dict_bgp_as[leaf] = str(bgp_as)

    return dict_bgp_as


def vrouter_interface_ibgp_add(module, switch_name, interface_ip, neighbor_ip,
                               remote_as, interface_ipv6=None, neighbor_ipv6=None):
    """
    Method to create interfaces and add ibgp neighbors.
    :param module: The Ansible module to fetch input parameters.
    :param switch_name: The name of the switch to run interface.
    :param interface_ip: Interface ip to create a vrouter interface.
    :param neighbor_ip: Neighbor_ip for the ibgp neighbor.
    :param interface_ipv6: Interface ipv6 to create a vrouter interface.
    :param neighbor_ipv6: Neighbor_ipv6 for the ibgp neighbor.
    :param remote_as: Bgp-as for remote switch.
    :return: String describing if ibgp neighbours got added or already exists.
    """
    global CHANGED_FLAG
    output = ''
    vlan_id = module.params['pn_ibgp_vlan']
    pim_ssm = module.params['pn_pim_ssm']

    cli = pn_cli(module)
    clicopy = cli
    cli += ' switch %s vlan-show format id no-show-headers ' % switch_name
    existing_vlans = run_cli(module, cli).split()

    if vlan_id not in existing_vlans:
        cli = clicopy
        cli += ' switch %s vlan-create id %s scope local ' % (switch_name,
                                                              vlan_id)
        run_cli(module, cli)

        output += ' %s: Created vlan with id %s \n' % (switch_name, vlan_id)
        CHANGED_FLAG.append(True)

    cli = clicopy
    cli += ' vrouter-show location %s format name' % switch_name
    cli += ' no-show-headers'
    vrouter = run_cli(module, cli).split()[0]

    cli = clicopy
    cli += ' vrouter-interface-show ip %s ' % interface_ip
    if interface_ipv6:
        cli += 'ip2 %s ' % interface_ipv6
    cli += 'vlan %s' % vlan_id
    cli += ' format switch no-show-headers'
    existing_vrouter_interface = run_cli(module, cli).split()

    if vrouter not in existing_vrouter_interface:
        cli = clicopy
        cli += 'vrouter-interface-add vrouter-name %s ' % vrouter
        cli += 'ip %s ' % interface_ip
        if interface_ipv6:
            cli += 'ip2 %s ' % interface_ipv6
        if pim_ssm == True:
            cli += ' pim-cluster '
        if module.params['pn_jumbo_frames'] == True:
            cli += ' mtu 9216'
        cli += 'vlan %s ' % vlan_id
        run_cli(module, cli)

        output += ' %s: Added vrouter interface with ip %s ip2 %s on %s \n' % (
            switch_name, interface_ip, interface_ipv6, vrouter
        )
        CHANGED_FLAG.append(True)

    neighbor_ip = neighbor_ip.split('/')[0]
    cli = clicopy
    cli += ' vrouter-bgp-show remote-as ' + remote_as
    cli += ' neighbor %s format switch no-show-headers' % neighbor_ip
    already_added = run_cli(module, cli).split()

    if vrouter not in already_added:
        cli = clicopy
        cli += ' vrouter-bgp-add vrouter-name %s' % vrouter
        cli += ' neighbor %s remote-as %s next-hop-self' % (neighbor_ip,
                                                            remote_as)
        if module.params['pn_bfd']:
            cli += ' bfd '

        if 'Success' in run_cli(module, cli):
            output += ' %s: Added iBGP neighbor %s for %s \n' % (switch_name,
                                                                 neighbor_ip,
                                                                 vrouter)
            CHANGED_FLAG.append(True)

    if neighbor_ipv6:
        neighbor_ipv6 = neighbor_ipv6.split('/')[0]
        cli = clicopy
        cli += ' vrouter-bgp-show remote-as ' + remote_as
        cli += ' neighbor %s format switch no-show-headers' % neighbor_ipv6
        already_added = run_cli(module, cli).split()

        if vrouter not in already_added:
            cli = clicopy
            cli += ' vrouter-bgp-add vrouter-name %s' % vrouter
            cli += ' neighbor %s remote-as %s next-hop-self' % (neighbor_ipv6,
                                                                remote_as)
            if module.params['pn_bfd']:
                cli += ' bfd '
    
            if 'Success' in run_cli(module, cli):
                output += ' %s: Added iBGP neighbor %s for %s \n' % (switch_name,
                                                                     neighbor_ipv6,
                                                                     vrouter)
            CHANGED_FLAG.append(True)

    return output


def assign_ibgp_interface(module, dict_bgp_as):
    """
    Method to create interfaces and add ibgp neighbors.
    :param module: The Ansible module to fetch input parameters.
    :param dict_bgp_as: The dictionary containing bgp-as of all switches.
    :return: The output of vrouter_interface_ibgp_add() method.
    """
    output = ''
    spine_list = module.params['pn_spine_list']
    leaf_list = module.params['pn_leaf_list']
    addr_type = module.params['pn_addr_type']
    ibgp_ipv4_range = module.params['pn_ibgp_ipv4_range']
    if addr_type == 'ipv4' or addr_type == 'ipv4_ipv6':
        cidr_v4 = int(module.params['pn_ebgp_cidr_ipv4'])
    subnet_v4 = module.params['pn_ebgp_subnet_ipv4']
    ibgp_ipv6_range = module.params['pn_ibgp_ipv6_range']
    if addr_type == 'ipv6' or addr_type == 'ipv4_ipv6':
        cidr_v6 = int(module.params['pn_cidr_ipv6'])
    subnet_v6 = module.params['pn_subnet_ipv6']

    cli = pn_cli(module)
    clicopy = cli

    if addr_type == 'ipv4' or addr_type == 'ipv4_ipv6':
        available_ips_ipv4 = calculate_link_ip_addresses_ipv4(ibgp_ipv4_range, cidr_v4, subnet_v4)

    if addr_type == 'ipv4_ipv6' or addr_type == 'ipv6':
        get_count = 2 if subnet_v6 == '127' else 3
        available_ips_ipv6 = calculate_link_ip_addresses_ipv6(ibgp_ipv6_range, cidr_v6, subnet_v6,
                                                              get_count)

    cli = pn_cli(module)
    clicopy = cli

    cli += ' cluster-show format name no-show-headers '
    cluster_list = run_cli(module, cli).split()


    if len(cluster_list) > 0 and cluster_list[0] != 'Success':
        for cluster in cluster_list:
            cli = clicopy
            cli += ' cluster-show name %s format cluster-node-1,' % cluster
            cli += 'cluster-node-2 no-show-headers'
            cluster_node_1, cluster_node_2 = run_cli(module, cli).split()

            if cluster_node_1 not in spine_list and cluster_node_1 in leaf_list:
                if addr_type == 'ipv4' or addr_type == 'ipv4_ipv6':
                    ipv4_1, ipv4_2 = available_ips_ipv4[0:2]
                    available_ips_ipv4.remove(ipv4_1)
                    available_ips_ipv4.remove(ipv4_2)
                if addr_type == 'ipv4_ipv6' or addr_type == 'ipv6':
                    ip_list = available_ips_ipv6.next()
                    if subnet_v6 == '127':
                        ipv6_1, ipv6_2 = ip_list[0:2]
                    else:
                        ipv6_1, ipv6_2 = ip_list[1:3]


            remote_as = dict_bgp_as[cluster_node_1]
            if cluster_node_1 not in spine_list and cluster_node_1 in leaf_list:
                if addr_type == 'ipv4':
                    output += vrouter_interface_ibgp_add(module, cluster_node_1,
                                                         ipv4_1, ipv4_2, remote_as)
                    output += vrouter_interface_ibgp_add(module, cluster_node_2,
                                                         ipv4_2, ipv4_1, remote_as)
                elif addr_type == 'ipv4_ipv6':
                    output += vrouter_interface_ibgp_add(module, cluster_node_1,
                                                         ipv4_1, ipv4_2, remote_as,
                                                         ipv6_1, ipv6_2)
                    output += vrouter_interface_ibgp_add(module, cluster_node_2,
                                                         ipv4_2, ipv4_1, remote_as,
                                                         ipv6_2, ipv6_1)
                else:
                    output += vrouter_interface_ibgp_add(module, cluster_node_1,
                                                         ipv6_1, ipv6_2, remote_as)
                    output += vrouter_interface_ibgp_add(module, cluster_node_2,
                                                         ipv6_2, ipv6_1, remote_as)


    else:
        output += ' No leaf clusters present to add iBGP \n'

    return output


def add_bgp_neighbor(module, dict_bgp_as):
    """
    Method to add bgp_neighbor to the vrouters.
    :param module: The Ansible module to fetch input parameters.
    :param dict_bgp_as: Dictionary containing bgp-as of all switches.
    :return: String describing if bgp neighbors got added or not.
    """
    global CHANGED_FLAG
    output = ''
    cli = pn_cli(module)
    addr_type = module.params['pn_addr_type']
    clicopy = cli

    spine_dict = dict()
    for spine in module.params['pn_spine_list']:
        spine_dict[spine] = list()

    for leaf in  module.params['pn_leaf_list']:
        leaf_input = list()
        cli = clicopy
        cli += ' vrouter-show location %s' % leaf
        cli += ' format name no-show-headers'
        vrouter_leaf = run_cli(module, cli).split()[0]

        cli = clicopy
        cli += 'vrouter-interface-show vrouter-name %s ' % vrouter_leaf
        cli += 'format l3-port,ip,'
        if addr_type == 'ipv4_ipv6':
            cli += 'ip2'
        cli += ' parsable-delim ,'
        vr_leaf_out = run_cli(module, cli).strip().split('\n')
        for vr in vr_leaf_out:
            vr = vr.strip().split(',')
            if vr[1]:
                leaf_input.append(vr)

        count = 0
        for spine in module.params['pn_spine_list']:
            spine_dict[spine].append(leaf_input[count])
            count += 1

    for spine in module.params['pn_spine_list']:
        for bgp_neighbor in spine_dict[spine]:
            cli = clicopy
            cli += ' vrouter-bgp-show remote-as ' + dict_bgp_as[bgp_neighbor[0][:-8]]
            cli += ' neighbor %s format switch no-show-headers ' % bgp_neighbor[2]
            already_added = run_cli(module, cli).split()

            if spine+'-vrouter' in already_added:
                output += ''
            else:
                cli = clicopy
                cli += ' vrouter-bgp-add vrouter-name ' + spine + '-vrouter'
                cli += ' neighbor %s remote-as %s ' % (bgp_neighbor[2],
                                                       dict_bgp_as[bgp_neighbor[0][:-8]])
                if module.params['pn_bfd']:
                    cli += ' bfd '

                if 'Success' in run_cli(module, cli):
                    output += ' %s: Added BGP Neighbor %s for %s \n' % (
                        spine, bgp_neighbor[1], spine+'vrouter'
                    )
                    CHANGED_FLAG.append(True)

            if addr_type == 'ipv4_ipv6':
                cli = clicopy
                cli += ' vrouter-bgp-show remote-as ' + dict_bgp_as[bgp_neighbor[0][:-8]]
                cli += ' neighbor %s format switch no-show-headers ' % bgp_neighbor[3]
                already_added = run_cli(module, cli).split()

                if spine+'-vrouter' in already_added:
                    output += ''
                else:
                    cli = clicopy
                    cli += ' vrouter-bgp-add vrouter-name ' + spine + '-vrouter'
                    cli += ' neighbor %s remote-as %s ' % (bgp_neighbor[3],
                                                           dict_bgp_as[bgp_neighbor[0][:-8]])
                    cli += ' multi-protocol ipv6-unicast'
                    if module.params['pn_bfd']:
                        cli += ' bfd '

                    if 'Success' in run_cli(module, cli):
                        output += ' %s: Added BGP Neighbor %s for %s \n' % (
                            spine, bgp_neighbor[1], spine+'vrouter'
                        )
                        CHANGED_FLAG.append(True)

    leaf_dict = dict()
    for leaf in module.params['pn_leaf_list']:
        leaf_dict[leaf] = list()

    for spine in  module.params['pn_spine_list']:
        spine_input = list()
        cli = clicopy
        cli += ' vrouter-show location %s' % spine
        cli += ' format name no-show-headers'
        vrouter_spine = run_cli(module, cli).split()[0]

        cli = clicopy
        cli += 'vrouter-interface-show vrouter-name %s ' % vrouter_spine
        cli += 'format l3-port,ip,ip2 parsable-delim ,'
        vr_spine_out = run_cli(module, cli).strip().split('\n')

        for vr in vr_spine_out:
            vr = vr.strip().split(',')
            if vr[1]:
                spine_input.append(vr)

        count = 0
        for leaf in module.params['pn_leaf_list']:
            leaf_dict[leaf].append(spine_input[count])
            count += 1

    for leaf in module.params['pn_leaf_list']:
        for bgp_neighbor in leaf_dict[leaf]:
            cli = clicopy
            cli += ' vrouter-bgp-show remote-as ' + dict_bgp_as[bgp_neighbor[0][:-8]]
            cli += ' neighbor %s format switch no-show-headers ' % bgp_neighbor[2]
            already_added = run_cli(module, cli).split()

            if leaf+'-vrouter' in already_added:
                output += ''
            else:
                cli = clicopy
                cli += ' vrouter-bgp-add vrouter-name ' + leaf + '-vrouter'
                cli += ' neighbor %s remote-as %s ' % (bgp_neighbor[2],
                                                       dict_bgp_as[bgp_neighbor[0][:-8]])
                if module.params['pn_bfd']:
                    cli += ' bfd '

                if 'Success' in run_cli(module, cli):
                    output += ' %s: Added BGP Neighbor %s for %s \n' % (
                        leaf, bgp_neighbor[1], leaf+'-vrouter'
                    )
                    CHANGED_FLAG.append(True)

            if addr_type == 'ipv4_ipv6':
                cli = clicopy
                cli += ' vrouter-bgp-show remote-as ' + dict_bgp_as[bgp_neighbor[0][:-8]]
                cli += ' neighbor %s format switch no-show-headers ' % bgp_neighbor[3]
                already_added = run_cli(module, cli).split()

                if leaf+'-vrouter' in already_added:
                    output += ''
                else:
                    cli = clicopy
                    cli += ' vrouter-bgp-add vrouter-name ' + leaf + '-vrouter'
                    cli += ' neighbor %s remote-as %s' % (bgp_neighbor[3],
                                                          dict_bgp_as[bgp_neighbor[0][:-8]])
                    cli += ' multi-protocol ipv6-unicast'
                    if module.params['pn_bfd']:
                        cli += ' bfd '

                    if 'Success' in run_cli(module, cli):
                        output += ' %s: Added BGP Neighbor %s for %s \n' % (
                            leaf, bgp_neighbor[1], leaf+'-vrouter'
                        )
                        CHANGED_FLAG.append(True)

    return output


def assign_router_id(module, vrouter_names):
    """
    Method to assign router-id to vrouters which is same as loopback ip.
    :param module: The Ansible module to fetch input parameters.
    :param vrouter_names: List of vrouter names.
    :return: String describing if router id got assigned or not.
    """
    global CHANGED_FLAG
    output = ''
    cli = pn_cli(module)
    clicopy = cli

    if len(vrouter_names) > 0:
        for vrouter in vrouter_names:
            cli = clicopy
            cli += ' vrouter-loopback-interface-show vrouter-name ' + vrouter
            cli += ' format ip no-show-headers '
            loopback_ip = run_cli(module, cli).split()

            if 'Success' not in loopback_ip and len(loopback_ip) > 0:
                loopback_ip.remove(vrouter)
                cli = clicopy
                cli += ' vrouter-modify name %s router-id %s ' % (
                    vrouter, loopback_ip[0])

                if 'Success' in run_cli(module, cli):
                    cli = clicopy
                    cli += ' vrouter-show name ' + vrouter
                    cli += ' format location no-show-headers '
                    switch = run_cli(module, cli).split()[0]

                    output += ' %s: Added router id %s to %s \n' % (
                        switch, loopback_ip[0], vrouter)

                    CHANGED_FLAG.append(True)

    return output


def configure_bgp(module, vrouter_names, dict_bgp_as, bgp_max, bgp_redis):
    """
    Method to add bgp_as, bgp_max_path and bgp_redistribute to the vrouters.
    :param module: The Ansible module to fetch input parameters.
    :param dict_bgp_as: Dictionary containing the bgp-as for all the switches.
    :param vrouter_names: List of vrouter names.
    :param bgp_max: Maxpath for bgp.
    :param bgp_redis: Bgp redistribute for bgp.
    :return: String describing if bgp config got added or not.
    """
    global CHANGED_FLAG
    output = ''
    cli = pn_cli(module)
    clicopy = cli

    for vrouter in vrouter_names:
        cli = clicopy
        cli += ' vrouter-show name ' + vrouter
        cli += ' format location no-show-headers '
        switch = run_cli(module, cli).split()[0]

        cli = clicopy
        cli += ' vrouter-modify name %s ' % vrouter
        cli += ' bgp-as %s ' % dict_bgp_as[switch]
        cli += ' bgp-max-paths %s ' % bgp_max
        cli += ' bgp-redistribute %s ' % bgp_redis
        if 'Success' in run_cli(module, cli):
            output += ' %s: Added bgp_redistribute %s ' % (switch, bgp_redis)
            output += 'bgp_as %s bgp_maxpath %s to %s\n' % (dict_bgp_as[switch],
                                                            bgp_max, vrouter)
            CHANGED_FLAG.append(True)

    return output


def find_non_clustered_leafs(module):
    """
    Method to find leafs which are not part of any cluster.
    :param module: The Ansible module to fetch input parameters.
    :return: List of non clustered leaf switches.
    """
    non_clustered_leafs = []
    cli = pn_cli(module)
    cli += ' cluster-show format cluster-node-1,cluster-node-2 '
    cli += ' no-show-headers '
    clustered_nodes = run_cli(module, cli).split()

    for leaf in module.params['pn_leaf_list']:
        if leaf not in clustered_nodes:
            non_clustered_leafs.append(leaf)

    return non_clustered_leafs


def create_cluster(module, name, node1, node2):
    """
    Method to create a cluster between two switches.
    :param module: The Ansible module to fetch input parameters.
    :param name: The name of the cluster to create.
    :param node1: First node of the cluster.
    :param node2: Second node of the cluster.
    :return: String describing if cluster got created or not.
    """
    global CHANGED_FLAG
    cli = pn_cli(module)
    clicopy = cli
    cli += ' switch %s cluster-show format name no-show-headers ' % node1
    cluster_list = run_cli(module, cli).split()
    if name not in cluster_list:
        cli = clicopy
        cli += ' switch %s cluster-create name %s ' % (node1, name)
        cli += ' cluster-node-1 %s cluster-node-2 %s ' % (node1, node2)
        if 'Success' in run_cli(module, cli):
            CHANGED_FLAG.append(True)
            return ' %s: Created %s \n' % (node1, name)
    else:
        return ''


def create_leaf_clusters(module):
    """
    Method to create cluster between two physically connected leaf switches.
    :param module: The Ansible module to fetch input parameters.
    :return: Output of create_cluster() method.
    """
    output = ''
    non_clustered_leafs = find_non_clustered_leafs(module)
    non_clustered_leafs_count = 0
    cli = pn_cli(module)
    clicopy = cli

    while non_clustered_leafs_count == 0:
        if len(non_clustered_leafs) == 0:
            non_clustered_leafs_count += 1
        else:
            node1 = non_clustered_leafs[0]
            non_clustered_leafs.remove(node1)

            cli = clicopy
            cli += ' switch %s lldp-show ' % node1
            cli += ' format sys-name no-show-headers '
            system_names = run_cli(module, cli).split()
            system_names = list(set(system_names))

            cli = clicopy
            cli += ' switch %s fabric-node-show ' % node1
            cli += ' format name no-show-headers '
            nodes_in_fabric = run_cli(module, cli).split()
            nodes_in_fabric = list(set(nodes_in_fabric))

            for system in system_names:
                if system not in nodes_in_fabric:
                    system_names.remove(system)

            terminate_flag = 0
            node_count = 0
            while (node_count < len(system_names)) and (terminate_flag == 0):
                node2 = system_names[node_count]
                if node2 in non_clustered_leafs:
                    # Cluster creation
                    cluster_name = node1 + '-to-' + node2 + '-cluster'
                    output += create_cluster(module, cluster_name, node1, node2)

                    non_clustered_leafs.remove(node2)
                    terminate_flag += 1

                node_count += 1

    return output


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_spine_list=dict(required=False, type='list'),
            pn_leaf_list=dict(required=False, type='list'),
            pn_addr_type=dict(required=False, type='str',
                                 choices=['ipv4', 'ipv4_ipv6', 'ipv6'], default='ipv4'),
            pn_bgp_as_range=dict(required=False, type='str', default='65000'),
            pn_bgp_redistribute=dict(required=False, type='str',
                                     choices=['none', 'static', 'connected',
                                              'rip', 'ospf'],
                                     default='none'),
            pn_bgp_maxpath=dict(required=False, type='str', default='16'),
            pn_ibgp_ipv4_range=dict(required=False, type='str',
                                  default='75.75.75.1'),
            pn_ebgp_cidr_ipv4=dict(required=False, type='str', default='24'),
            pn_ebgp_subnet_ipv4=dict(required=False, type='str', default='31'),
            pn_ibgp_ipv6_range=dict(required=False, type='str'),
            pn_jumbo_frames=dict(required=False, type='bool', default=False),
            pn_pim_ssm=dict(required=False, type='bool', default=False),
            pn_cidr_ipv6=dict(required=False, type='str', default='112'),
            pn_subnet_ipv6=dict(required=False, type='str', default='127'),
            pn_bfd=dict(required=False, type='bool', default=False),
            pn_ibgp_vlan=dict(required=False, type='str', default='4040'),
            pn_routing_protocol=dict(required=False, type='str',
                                     choices=['ebgp'], default='ebgp'),
        )
    )

    global CHANGED_FLAG
    routing_protocol = module.params['pn_routing_protocol']

    # Get the list of vrouter names.
    cli = pn_cli(module)
    cli += ' vrouter-show format name no-show-headers '
    vrouter_names = run_cli(module, cli).split()

#    message = assign_router_id(module, vrouter_names)
    message = create_leaf_clusters(module)

    if routing_protocol == 'ebgp':
        dict_bgp_as = find_bgp_as_dict(module)
        message += configure_bgp(module, vrouter_names, dict_bgp_as,
                                 module.params['pn_bgp_maxpath'],
                                 module.params['pn_bgp_redistribute'])
        message += add_bgp_neighbor(module, dict_bgp_as)
        message += assign_ibgp_interface(module, dict_bgp_as)

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
        msg='eBGP configuration succeeded',
        summary=results,
        exception='',
        failed=False,
        changed=True if True in CHANGED_FLAG else False,
        task='Configure eBGP'
    )

if __name__ == '__main__':
    main()

