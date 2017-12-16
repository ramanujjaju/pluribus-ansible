#!/usr/bin/python
""" PN CLI vflow-create/vflow-delete/vflow-modify """
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

DOCUMENTATION = """
---
module: pn_vflow
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to create/delete/modify a vflow.
description:
  - Execute vflow-create, vflow-delete or vflow-modify command. 
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
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - vFlow configuration command.
    required: True
    choices: ['create', 'delete', 'modify']
    type: str
  pn_name:
    description:
      - Name for the vFlow.
    required: True
    type: str
  pn_scope:
    description:
      - Scope is local or fabric.
    required: False
    choices: ['local', 'fabric']
    type: str
  pn_vflow_id:
    description:
      - ID assigned to the vFlow.
    required: False
    type: str
  pn_vnet:
    description:
      - VNET assigned to the vFlow.
    required: False
    type: str
  pn_l2net:
    description:
      - l2-net for the vFlow.
    required: False
    type: str
  pn_vlan:
    description:
      - VLAN for the vFlow.
    required: False
    type: str
  pn_inport:
    description:
      - Incoming port for the vFlow.
    required: False
    type: str
  pn_outport:
    description:
      - Outgoing port for the vFlow.
    required: False
    type: str
  pn_ether_type:
    description:
      - EtherType for the vFlow.
    required: False
    choices: ['ipv4', 'arp', 'wake', 'rarp', 'vlan', 'ipv6',
    'mpls-uni', 'mpls-multi', 'jumbo', 'aoe', 'dot1X',
    'lldp', 'lacp', 'ecp', 'macsec', 'ptp', 'fcoe',
    'fcoe-init', 'qinq']
    type: str
  pn_src_mac:
    description:
      - Source MAC address for the vFlow.
    required: False
    type: str
  pn_src_mac_mask:
    description:
      - Source MAC address to use as a wildcard mask.
    required: False
    type: str
  pn_dst_mac:
    description:
      - Destination MAC address for the vFlow.
    required: False
    type: str
  pn_dst_mac_mask:
    description:
      - Destination MAC address to use as a wildcard mask.
    required: False
    type: str
  pn_src_ip:
    description:
      - Source IP address for the vFlow.
    required: False
    type: str
  pn_src_ip_mask:
    description:
      - Source IP address wildcard mask for the vFlow.
    required: False
    type: str
  pn_dst_ip:
    description:
      - Destination IP address for the vFlow.
    required: False
    type: str
  pn_dst_ip_mask:
    description:
      - Destination IP address wildcard mask for the vFlow.
    required: False
    type: str
  pn_src_port:
    description:
      - Layer 3 protocol source port for the vFlow.
    required: False
    type: str
  pn_src_port_mask:
    description:
      - Source port mask.
    required: False
    type: str
  pn_dst_port:
    description:
      - Layer 3 protocol destination port for the vFlow.
    required: False
    type: str
  pn_dst_port_mask:
    description:
      - Destination port mask.
    required: False
    type: str
  pn_dscp_start:
    description:
      - 6bit Differentiated Services Code Point (DSCP) start number.
    required: False
    type: str
  pn_dscp_end:
    description:
      - 6bit Differentiated Services Code Point (DSCP) end number.
    required: False
    type: str
  pn_dscp:
    description:
      - 6bit Differentiated Services Code Point (DSCP) 
      for the vFlow with range 0 to 63.
    required: False
    type: str
  pn_dscp_map:
    description:
      - DSCP map to apply on the flow. Please reapply 
      if map priorities are updated.
    required: False
    type: str
  pn_tos_start:
    description:
      - Start Type of Service (ToS) number.
    required: False
    type: str
  pn_tos_end:
    description:
      - The ending Type of Service (ToS) number.
    required: False
    type: str
  pn_tos:
    description:
      - ToS number for the vFlow.
    required: False
    type: str
  pn_vlan_pri:
    description:
      - Priority for the VLAN - 0 to 7.
    required: False
    type: str
  pn_ttl:
    description:
      - Time-to-live.
    required: False
    type: str
  pn_proto:
    description:
      - Layer 3 protocol for the vFlow.
    required: False
    choices: ['tcp', 'udp', 'icmp', 'igmp', 'ip', 'icmpv6']
    type: str
  pn_tcp_flags:
    description:
      - TCP Control Flags.
    required: False
    choices: ['fin', 'syn', 'rst', 'push', 'ack', 'urg',
    'ece', 'cwr']
    type: str
  pn_flow_class:
    description:
      - vFlow class name.
    required: False
    type: str
  pn_ingress_tunnel:
    description:
      - Tunnel for the ingress traffic.
    required: False
    type: str
  pn_egress_tunnel:
    description:
      - Tunnel for egress traffic.
    required: False
    type: str
  pn_bw_min:
    description:
      - Minimum bandwidth in Gbps.
    required: False
    type: str
  pn_bw_max:
    description:
      - Maximum bandwidth in Gbps.
    required: False
    type: str
  pn_burst_size:
    description:
      - Committed burst size in bytes.
    required: False
    type: str
  pn_vrouter_name:
    description:
      - Name of the vrouter service.
    required: False
    type: str
  pn_precedence:
    description:
      - Traffic priority value between 2 and 15.
    required: False
    type: str
  pn_vflow_action:
    description:
      - Forwarding action to apply to the vFlow.
    required: False
    choices: ['none', 'drop', 'to-port', 'to-cpu', 'trap',
    'copy-to-cpu', 'copy-to-port', 'check', 'setvlan',
    'add-outer-vlan', 'set-tpid', 'to-port-set-vlan',
    'tunnel-pkt', 'set-tunnel-id', 'to-span', 'cpu-rx',
    'cpu-rx-tx', 'set-metadata', 'set-dscp', 'decap',
    'set-dmac', 'to-next-hop-ip', 'set-dmac-to-port',
    'to-ports-and-cpu', 'set-vlan-pri', 'tcp-seq-offset',
    'tcp-ack-offset', 'l3-to-cpu-switch', 'set-smac',
    'drop-cancel-trap']
    type: str
  pn_action_value:
    description:
      - Optional value argument between 1 and 64.
    required: False
    type: str
  pn_action_mac_value:
    description:
      - MAC address value.
    required: False
    type: str
  pn_action_nexthop_ip_value:
    description:
      - Next-hop IP address for packet redirection.
    required: False
    type: str
  pn_action_ports_value:
    description:
      - Action to ports value.
    required: False
    type: str
  pn_mirror:
    description:
      - Mirror configuration name.
    required: False
    type: str
  pn_process_mirror:
    description:
      - vFlow processes mirrored traffic or not.
    required: False
    type: bool
  pn_log_packets:
    description:
      - Log the packets in the flow.
    required: False
    type: bool
  pn_packet_log_max:
    description:
      - Maximum packet count for log rotation in the flow.
    required: False
    type: str
  pn_log_stats:
    description:
      - Log packet statistics for the flow.
    required: False
    type: bool
  pn_stats_interval:
    description:
      - Interval to update packet statistics for the log(seconds).
    required: False
    type: str
  pn_dur:
    description:
      - Minimum duration required for the flow to be captured(seconds).
    required: False
    type: str
  pn_metadata:
    description:
      - Metadata number for the vFlow.
    required: False
    type: str
  pn_transient:
    description:
      - Capture transient flows.
    required: False
    type: bool
  pn_vxlan:
    description:
      - Name of the VXLAN.
    required: False
    type: str
  pn_vxlan_ether_type:
    description:
      - EtherType of the VXLAN.
    required: False
    choices: ['ipv4', 'arp', 'wake', 'rarp', 'vlan', 'ipv6',
    'mpls-uni', 'mpls-multi', 'jumbo', 'aoe', 'dot1X',
    'lldp', 'lacp', 'ecp', 'macsec', 'ptp', 'fcoe',
    'fcoe-init', 'qinq']
    type: str
  pn_vxlan_proto:
    description:
      - Protocol type for the VXLAN.
    required: False
    choices: ['tcp', 'udp', 'icmp', 'igmp', 'ip', 'icmpv6']
    type: str
  pn_set_src_ip:
    description:
      - Set src ip of ipv4 packets.
    required: False
    type: str
  pn_set_dst_ip:
    description:
      - Set dst ip of ipv4 packets.
    required: False
    type: str
  pn_set_src_port:
    description:
      - Set src port of ipv4 packets.
    required: False
    type: str
  pn_set_dst_port:
    description:
      - Set dst port of ipv4 packets.
    required: False
    type: str
  pn_udf_name1:
    description:
      - Udf name.
    required: False
    type: str
  pn_udf_data1:
    description:
      - Udf data.
    required: False
    type: str
  pn_udf_data1_mask:
    description:
      - Mask for udf data.
    required: False
    type: str
  pn_udf_name2:
    description:
      - Udf name.
    required: False
    type: str
  pn_udf_data2:
    description:
      - Udf data.
    required: False
    type: str
  pn_udf_data2_mask:
    description:
      - Mask for udf data.
    required: False
    type: str
  pn_udf_name3:
    description:
      - Udf name.
    required: False
    type: str
  pn_udf_data3:
    description:
      - Udf data.
    required: False
    type: str
  pn_udf_data3_mask:
    description:
      - Mask for udf data.
    required: False
    type: str
  pn_enable:
    description:
      - Enable/disable flows in hardware.
    required: False
    type: bool
  pn_table_name:
    description:
      - Table name.
    required: False
    type: str
  pn_cpu_class:
    description:
      - CPU class name.
    required: False
    type: str
"""

EXAMPLES = """
- name: create vflow
  pn_vflow:
    pn_action: "create"
    pn_name: "tcp-flow"
    pn_scope: "fabric"
    pn_src_ip: "10.10.10.1"
    pn_src_ip_mask: "24"
    pn_proto: "tcp"
    pn_tcp_flags: "syn"

- name: delete vflow
  pn_vflow:
    pn_action: "delete"
    pn_name: "tcp-flow"

- name: modify vflow
  pn_vflow:
    pn_action: "modify"
    pn_name: "tcp-flow"
    pn_tcp_flags: "ack"
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the vflow command.
  returned: always
  type: list
stderr:
  description: set of error responses from the vflow command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
"""

VFLOW_EXISTS = None

def pn_cli(module):
    """
    This method is to generate the cli portion to launch the Netvisor cli.
    It parses the username, password, switch parameters from module.
    :param module: The Ansible module to fetch username, password and switch
    :return: returns the cli string for further processing
    """
    username = module.params['pn_cliusername']
    password = module.params['pn_clipassword']
    cliswitch = module.params['pn_cliswitch']

    cli = '/usr/bin/cli --quiet '

    if username and password:
        cli += '--user "%s":"%s" ' % (username, password)

    if cliswitch:
        cli += ' switch ' + cliswitch

    return cli


def check_cli(module):
    """
    This method checks for idempotency using the vflow-show command.
    If a vFlow already exists on the given switch, return VFLOW_EXISTS as
    True else False.

    :param module: The Ansible module to fetch input parameters
    :return Global Booleans: VFLOW_EXISTS
    """
    name = module.params['pn_name']
    show_cli = pn_cli(module)
    # Global flags
    global VFLOW_EXISTS

    cliswitch = module.params['pn_cliswitch']
    if cliswitch:
        show_cli = show_cli.replace('switch ', '')
        show_cli = show_cli.replace(cliswitch, '')

    # Check for any vRouters on the switch
    check_vflow = show_cli + ' vflow-show '
    check_vflow += 'format name no-show-headers'
    check_vflow = shlex.split(check_vflow)
    out = module.run_command(check_vflow)[1]

    VFLOW_EXISTS = True if name in out else False


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
            msg="vFlow %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="vFlow %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="vFlow %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliusername=dict(required=False, type='str', no_log=True),
            pn_clipassword=dict(required=False, type='str', no_log=True),
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['create', 'delete', 'modify']),
            pn_name=dict(required=True, type='str'),
            pn_scope=dict(required=True, type='str',
                          choices=['local', 'fabric']),
            pn_vflow_id=dict(type='str'),
            pn_vnet=dict(type='str'),
            pn_l2net=dict(type='str'),
            pn_vlan=dict(type='str'),
            pn_inport=dict(type='str'),
            pn_outport=dict(type='str'),
            pn_ether_type=dict(type='str',
                               choices=['ipv4', 'arp', 'wake', 'rarp', 'vlan', 'ipv6',
                                        'mpls-uni', 'mpls-multi', 'jumbo', 'aoe', 'dot1X',
                                        'lldp', 'lacp', 'ecp', 'macsec', 'ptp', 'fcoe',
                                        'fcoe-init', 'qinq']),
            pn_src_mac=dict(type='str'),
            pn_src_mac_mask=dict(type='str'),
            pn_dst_mac=dict(type='str'),
            pn_dst_mac_mask=dict(type='str'),
            pn_src_ip=dict(type='str'),
            pn_src_ip_mask=dict(type='str'),
            pn_dst_ip=dict(type='str'),
            pn_dst_ip_mask=dict(type='str'),
            pn_src_port=dict(type='str'),
            pn_src_port_mask=dict(type='str'),
            pn_dst_port=dict(type='str'),
            pn_dst_port_mask=dict(type='str'),
            pn_dscp_start=dict(type='str'),
            pn_dscp_end=dict(type='str'),
            pn_dscp=dict(type='str'),
            pn_dscp_map=dict(type='str'),
            pn_tos_start=dict(type='str'),
            pn_tos_end=dict(type='str'),
            pn_tos=dict(type='str'),
            pn_vlan_pri=dict(type='str'),
            pn_ttl=dict(type='str'),
            pn_proto=dict(type='str',
                          choices=['tcp', 'udp', 'icmp', 'igmp', 'ip', 'icmpv6']),
            pn_tcp_flags=dict(type='str',
                              choices=['fin', 'syn', 'rst', 'push', 'ack',
                                       'urg', 'ece', 'cwr']),
            pn_flow_class=dict(type='str'),
            pn_ingress_tunnel=dict(type='str'),
            pn_egress_tunnel=dict(type='str'),
            pn_bw_min=dict(type='str'),
            pn_bw_max=dict(type='str'),
            pn_burst_size=dict(type='str'),
            pn_vrouter_name=dict(type='str'),
            pn_precedence=dict(type='str'),
            pn_vflow_action=dict(type='str',
                                 choices=['none', 'drop', 'to-port', 'to-cpu', 'trap',
                                          'copy-to-cpu', 'copy-to-port', 'check', 'setvlan',
                                          'add-outer-vlan', 'set-tpid', 'to-port-set-vlan',
                                          'tunnel-pkt', 'set-tunnel-id', 'to-span', 'cpu-rx',
                                          'cpu-rx-tx', 'set-metadata', 'set-dscp', 'decap',
                                          'set-dmac', 'to-next-hop-ip', 'set-dmac-to-port',
                                          'to-ports-and-cpu', 'set-vlan-pri', 'tcp-seq-offset',
                                          'tcp-ack-offset', 'l3-to-cpu-switch', 'set-smac',
                                          'drop-cancel-trap']),
            pn_action_value=dict(type='str'),
            pn_action_mac_value=dict(type='str'),
            pn_action_nexthop_ip_value=dict(type='str'),
            pn_action_ports_value=dict(type='str'),
            pn_mirror=dict(type='str'),
            pn_process_mirror=dict(type='bool'),
            pn_log_packets=dict(type='bool'),
            pn_packet_log_max=dict(type='str'),
            pn_log_stats=dict(type='bool'),
            pn_stats_interval=dict(type='str'),
            pn_dur=dict(type='str'),
            pn_metadata=dict(type='str'),
            pn_transient=dict(type='bool'),
            pn_vxlan=dict(type='str'),
            pn_vxlan_ether_type=dict(type='str',
                                     choices=['ipv4', 'arp', 'wake', 'rarp', 'vlan', 'ipv6',
                                              'mpls-uni', 'mpls-multi', 'jumbo', 'aoe', 'dot1X',
                                              'lldp', 'lacp', 'ecp', 'macsec', 'ptp', 'fcoe',
                                              'fcoe-init', 'qinq']),
            pn_vxlan_proto=dict(type='str',
                                choices=['tcp', 'udp', 'icmp', 'igmp', 'ip', 'icmpv6']),
            pn_set_src_ip=dict(type='str'),
            pn_set_dst_ip=dict(type='str'),
            pn_set_src_port=dict(type='str'),
            pn_set_dst_port=dict(type='str'),
            pn_udf_name1=dict(type='str'),
            pn_udf_data1=dict(type='str'),
            pn_udf_data1_mask=dict(type='str'),
            pn_udf_name2=dict(type='str'),
            pn_udf_data2=dict(type='str'),
            pn_udf_data2_mask=dict(type='str'),
            pn_udf_name3=dict(type='str'),
            pn_udf_data3=dict(type='str'),
            pn_udf_data3_mask=dict(type='str'),
            pn_enable=dict(type='bool'),
            pn_table_name=dict(type='str'),
            pn_cpu_class=dict(type='str'),
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    command = 'vflow-' + action
    name = module.params['pn_name']
    scope = module.params['pn_scope']
    vflow_id = module.params['pn_vflow_id']
    vnet = module.params['pn_vnet']
    l2net = module.params['pn_l2net']
    vlan = module.params['pn_vlan']
    inport = module.params['pn_inport']
    outport = module.params['pn_outport']
    ether_type = module.params['pn_ether_type']
    src_mac = module.params['pn_src_mac']
    src_mac_mask = module.params['pn_src_mac_mask']
    dst_mac = module.params['pn_dst_mac']
    dst_mac_mask = module.params['pn_dst_mac_mask']
    src_ip = module.params['pn_src_ip']
    src_ip_mask = module.params['pn_src_ip_mask']
    dst_ip = module.params['pn_dst_ip']
    dst_ip_mask = module.params['pn_dst_ip_mask']
    src_port = module.params['pn_src_port']
    src_port_mask = module.params['pn_src_port_mask']
    dst_port = module.params['pn_dst_port']
    dst_port_mask = module.params['pn_dst_port_mask']
    dscp_start = module.params['pn_dscp_start']
    dscp_end = module.params['pn_dscp_end']
    dscp = module.params['pn_dscp']
    dscp_map = module.params['pn_dscp_map']
    tos_start = module.params['pn_tos_start']
    tos_end = module.params['pn_tos_end']
    tos = module.params['pn_tos']
    vlan_pri = module.params['pn_vlan_pri']
    ttl = module.params['pn_ttl']
    proto = module.params['pn_proto']
    tcp_flags = module.params['pn_tcp_flags']
    flow_class = module.params['pn_flow_class']
    ingress_tunnel = module.params['pn_ingress_tunnel']
    egress_tunnel = module.params['pn_egress_tunnel']
    bw_min = module.params['pn_bw_min']
    bw_max = module.params['pn_bw_max']
    burst_size = module.params['pn_burst_size']
    vrouter_name = module.params['pn_vrouter_name']
    precedence = module.params['pn_precedence']
    vflow_action = module.params['pn_vflow_action']
    action_value = module.params['pn_action_value']
    action_mac_value = module.params['pn_action_mac_value']
    action_nexthop_ip_value = module.params['pn_action_nexthop_ip_value']
    action_ports_value = module.params['pn_action_ports_value']
    mirror = module.params['pn_mirror']
    process_mirror = module.params['pn_process_mirror']
    log_packets = module.params['pn_log_packets']
    packet_log_max = module.params['pn_packet_log_max']
    log_stats = module.params['pn_log_stats']
    stats_interval = module.params['pn_stats_interval']
    dur = module.params['pn_dur']
    metadata = module.params['pn_metadata']
    transient = module.params['pn_transient']
    vxlan = module.params['pn_vxlan']
    vxlan_ether_type = module.params['pn_vxlan_ether_type']
    vxlan_proto = module.params['pn_vxlan_proto']
    set_src_ip = module.params['pn_set_src_ip']
    set_dst_ip = module.params['pn_set_dst_ip']
    set_src_port = module.params['pn_set_src_port']
    set_dst_port = module.params['pn_set_dst_port']
    udf_name1 = module.params['pn_udf_name1']
    udf_data1 = module.params['pn_udf_data1']
    udf_data1_mask = module.params['pn_udf_data1_mask']
    udf_name2 = module.params['pn_udf_name2']
    udf_data2 = module.params['pn_udf_data2']
    udf_data2_mask = module.params['pn_udf_data2_mask']
    udf_name3 = module.params['pn_udf_name3']
    udf_data3 = module.params['pn_udf_data3']
    udf_data3_mask = module.params['pn_udf_data3_mask']
    enable = module.params['pn_enable']
    table_name = module.params['pn_table_name']
    cpu_class = module.params['pn_cpu_class']

    # Building the CLI command string
    cli = pn_cli(module)
    if action == 'delete':
        check_cli(module)
        if VFLOW_EXISTS is False:
            module.exit_json(
                skipped=True,
                msg='vFlow %s does not exist' % name
            )
        cli += ' %s name %s ' % (command, name)
        if vflow_id:
            cli += ' id %s ' % vflow_id

    else:
        check_cli(module)
        if action == 'modify':
            if VFLOW_EXISTS is False:
                module.exit_json(
                    skipped=True,
                    msg='vFlow %s does not exist' % name
                )
            cli += ' %s name %s ' % (command, name)
            if vflow_id:
                cli += ' id %s ' % vflow_id

        if action == 'create':
            if VFLOW_EXISTS is True:
                module.exit_json(
                    skipped=True,
                    msg='vFlow %s already exists ' % name
                )
            cli += ' %s name %s scope %s ' % (command, name, scope)
            if vnet:
                cli += ' vnet ' + vnet
            if l2net:
                cli += ' l2-net ' + l2net
            if vlan:
                cli += ' vlan ' + vlan

        if inport:
            cli += ' in-port ' + inport

        if outport:
            cli += ' out-port ' + outport

        if ether_type:
            cli += ' ether-type ' + ether_type

        if src_mac:
            cli += ' src-mac ' + src_mac

        if src_mac_mask:
            cli += ' src-mac-mask ' + src_mac_mask

        if dst_mac:
            cli += ' dst-mac ' + dst_mac

        if dst_mac_mask:
            cli += ' dst-mac-mask ' + dst_mac_mask

        if src_ip:
            cli += ' src-ip ' + src_ip

        if src_ip_mask:
            cli += ' src-ip-mask ' + src_ip_mask

        if dst_ip:
            cli += ' dst-ip ' + dst_ip

        if dst_ip_mask:
            cli += ' dst-ip-mask ' + dst_ip_mask

        if src_port:
            cli += ' src-port ' + src_port

        if src_port_mask:
            cli += ' src-port-mask ' + src_port_mask

        if dst_port:
            cli += ' dst-port ' + dst_port

        if dst_port_mask:
            cli += ' dst-port-mask ' + dst_port_mask

        if dscp_start:
            cli += ' dscp-start ' + dscp_start

        if dscp_end:
            cli += ' dscp-end ' + dscp_end

        if dscp:
            cli += ' dscp ' + dscp

        if dscp_map:
            cli += ' dscp-map ' + dscp_map

        if tos_start:
            cli += ' tos-start ' + tos_start

        if tos_end:
            cli += ' tos-end ' + tos_end

        if tos:
            cli += ' tos ' + tos

        if vlan_pri:
            cli += ' vlan-pri ' + vlan_pri

        if ttl:
            cli += ' ttl ' + ttl

        if proto:
            cli += ' proto ' + proto

        if tcp_flags:
            cli += ' tcp-flags ' + tcp_flags

        if flow_class:
            cli += ' flow-class ' + flow_class

        if ingress_tunnel:
            cli += ' ingress-tunnel ' + ingress_tunnel

        if egress_tunnel:
            cli += ' egress-tunnel ' + egress_tunnel

        if bw_min:
            cli += ' bw-min ' + bw_min

        if bw_max:
            cli += ' bw-max ' + bw_max

        if burst_size:
            cli += ' burst-size ' + burst_size

        if vrouter_name:
            cli += ' vrouter-name ' + vrouter_name

        if precedence:
            cli += ' precedence ' + precedence

        if vflow_action:
            cli += ' action ' + vflow_action

        if action_value:
            cli += ' action-value ' + action_value

        if action_mac_value:
            cli += ' action-set-mac-value ' + action_mac_value

        if action_nexthop_ip_value:
            cli += ' action-to-next-hop-ip-value ' + action_nexthop_ip_value

        if action_ports_value:
            cli += ' action-to-ports-value ' + action_ports_value

        if mirror:
            cli += ' mirror ' + mirror

        if process_mirror is True:
            cli += ' process-mirror '
        if process_mirror is False:
            cli += ' no-process-mirror '

        if log_packets is True:
            cli += ' log-packets '
        if log_packets is False:
            cli += ' no-log-packets '

        if packet_log_max:
            cli += ' packet-log-max ' + packet_log_max

        if log_stats is True:
            cli += ' log-stats '
        if log_stats is False:
            cli += ' no-log-stats '

        if stats_interval:
            cli += ' stats-interval ' + stats_interval

        if dur:
            cli += ' dur ' + dur

        if metadata:
            cli += ' metadata ' + metadata

        if transient is True:
            cli += ' transient '
        if transient is False:
            cli += ' no-transient '

        if vxlan:
            cli += ' vxlan ' + vxlan

        if vxlan_ether_type:
            cli += ' vxlan-ether-type ' + vxlan_ether_type

        if vxlan_proto:
            cli += ' vxlan-proto ' + vxlan_proto

        if set_src_ip:
            cli += ' set-src ' + set_src_ip

        if set_dst_ip:
            cli += ' set-dst ' + set_dst_ip

        if set_src_port:
            cli += ' set-src-port ' + set_src_port

        if set_dst_port:
            cli += ' set-dst-port ' + set_dst_port

        if udf_name1:
            cli += ' udf-name1 ' + udf_name1

        if udf_data1:
            cli += ' udf-data1 ' + udf_data1

        if udf_data1_mask:
            cli += ' udf-data1-mask ' + udf_data1_mask

        if udf_name2:
            cli += ' udf-name2 ' + udf_name2

        if udf_data2:
            cli += ' udf-data2 ' + udf_data2

        if udf_data2_mask:
            cli += ' udf-data2-mask ' + udf_data2_mask

        if udf_name3:
            cli += ' udf-name3 ' + udf_name3

        if udf_data3:
            cli += ' udf-data3 ' + udf_data3

        if udf_data3_mask:
            cli += ' udf-data3-mask ' + udf_data3_mask

        if enable is True:
            cli += ' enable '
        if enable is False:
            cli += ' no-enable '

        if table_name:
            cli += ' table-name ' + table_name

        if cpu_class:
            cli += ' cpu-class ' + cpu_class

    run_cli(module, cli)

if __name__ == '__main__':
    main()
