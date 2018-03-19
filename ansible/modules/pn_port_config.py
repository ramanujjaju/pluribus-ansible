#!/usr/bin/python
""" PN CLI port-config-modify """

# Copyright 2018 Pluribus Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import shlex
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pn_nvos import pn_cli

DOCUMENTATION = """
---
module: pn_port_config
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to modify port-config.
description:
  - C(modify): modify a port configuration
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - port-config configuration command.
    required: true
    choices: ['modify']
    type: str
  pn_intf:
    description:
      - physical interface
    required: false
    type: str
  pn_crc_check_enable:
    description:
      - CRC check on ingress and rewrite on egress
    required: false
    type: bool
  pn_dscp_map:
    description:
      - DSCP map name to enable on port
    required: false
    type: str
  pn_autoneg:
    description:
      - physical port autonegotiation
    required: false
    type: bool
  pn_speed:
    description:
      - physical port speed
    required: false
    choices: ['disable', '10m', '100m', '1g', '2.5g', '10g', '25g', '40g', '50g', '100g']
  pn_port:
    description:
      - physical port
    required: false
    type: str
  pn_vxlan_termination:
    description:
      - physical port vxlan termination setting
    required: false
    type: bool
  pn_pause:
    description:
      - physical port pause
    required: false
    type: bool
  pn_loopback:
    description:
      - physical port loopback
    required: false
    type: bool
  pn_loop_vlans:
    description:
      - looping vlans
    required: false
    type: str
  pn_routing:
    description:
      - routing
    required: false
    type: bool
  pn_edge_switch:
    description:
      - physical port edge switch
    required: false
    type: bool
  pn_enable:
    description:
      - physical port enable
    required: false
    type: bool
  pn_description:
    description:
      - physical port description
    required: false
    type: str
  pn_host_enable:
    description:
      - Host facing port control setting
    required: false
    type: bool
  pn_allowed_tpid:
    description:
      - Allowed TPID in addition to 0x8100 on Vlan header
    required: false
    choices: ['q-in-q', 'q-in-q-old']
  pn_mirror_only:
    description:
      - physical port mirror only
    required: false
    type: bool
  pn_reflect:
    description:
      - physical port reflection
    required: false
    type: bool
  pn_jumbo:
    description:
      - jumbo frames on physical port
    required: false
    type: bool
  pn_egress_rate_limit:
    description:
      - max egress port data rate limit
    required: false
    type: str
  pn_eth_mode:
    description:
      - physical Ethernet mode
    required: false
    choices: ['1000base-x', 'sgmii']
  pn_fabric_guard:
    description:
      - Fabric guard contfiguration
    required: false
    type: bool
  pn_local_switching:
    description:
      - no-local-switching port cannot bridge traffic to another no-local-switching port
    required: false
    type: bool
  pn_lacp_priority:
    description:
      - LACP priority from 1 to 65535 - default 32768
    required: false
    type: str
  pn_send_port:
    description:
      - send port
    required: false
    type: str
  pn_port_mac_address:
    description:
      - physical port MAC Address
    required: false
    type: str
  pn_bw_bps:
    description:
      - trunk bandwidth in bps
    required: false
    type: str
"""

EXAMPLES = """
- name: port config modify
  pn_port_config:
    pn_cliswitch: "{{ inventory_hostname }}"
    pn_action: "modify"
    pn_port: "all"
    pn_dscp_map: "verizon_qos"
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the port-config command.
  returned: always
  type: list
stderr:
  description: set of error responses from the port-config command.
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
            msg="port-config %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="port-config %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="port-config %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str', choices=['modify']),
            pn_intf=dict(required=False, type='str'),
            pn_crc_check_enable=dict(required=False, type='bool'),
            pn_dscp_map=dict(required=False, type='str'),
            pn_autoneg=dict(required=False, type='bool'),
            pn_speed=dict(required=False, type='str', choices=['disable',
                                                      '10m', '100m', '1g',
                                                      '2.5g', '10g', '25g',
                                                      '40g', '50g', '100g']),
            pn_port=dict(required=False, type='str'),
            pn_vxlan_termination=dict(required=False, type='bool'),
            pn_pause=dict(required=False, type='bool'),
            pn_loopback=dict(required=False, type='bool'),
            pn_loop_vlans=dict(required=False, type='str'),
            pn_routing=dict(required=False, type='bool'),
            pn_edge_switch=dict(required=False, type='bool'),
            pn_enable=dict(required=False, type='bool'),
            pn_description=dict(required=False, type='str'),
            pn_host_enable=dict(required=False, type='bool'),
            pn_allowed_tpid=dict(required=False, type='str',
                                 choices=['q-in-q', 'q-in-q-old']),
            pn_mirror_only=dict(required=False, type='bool'),
            pn_reflect=dict(required=False, type='bool'),
            pn_jumbo=dict(required=False, type='bool'),
            pn_egress_rate_limit=dict(required=False, type='str'),
            pn_eth_mode=dict(required=False, type='str',
                             choices=['1000base-x', 'sgmii']),
            pn_fabric_guard=dict(required=False, type='bool'),
            pn_local_switching=dict(required=False, type='bool'),
            pn_lacp_priority=dict(required=False, type='str'),
            pn_send_port=dict(required=False, type='str'),
            pn_port_mac_address=dict(required=False, type='str'),
            pn_bw_bps=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    switch = module.params['pn_cliswitch']
    mod_action = module.params['pn_action']
    intf = module.params['pn_intf']
    crc_check_enable = module.params['pn_crc_check_enable']
    dscp_map = module.params['pn_dscp_map']
    autoneg = module.params['pn_autoneg']
    speed = module.params['pn_speed']
    port = module.params['pn_port']
    vxlan_termination = module.params['pn_vxlan_termination']
    pause = module.params['pn_pause']
    loopback = module.params['pn_loopback']
    loop_vlans = module.params['pn_loop_vlans']
    routing = module.params['pn_routing']
    edge_switch = module.params['pn_edge_switch']
    enable = module.params['pn_enable']
    description = module.params['pn_description']
    host_enable = module.params['pn_host_enable']
    allowed_tpid = module.params['pn_allowed_tpid']
    mirror_only = module.params['pn_mirror_only']
    reflect = module.params['pn_reflect']
    jumbo = module.params['pn_jumbo']
    egress_rate_limit = module.params['pn_egress_rate_limit']
    eth_mode = module.params['pn_eth_mode']
    fabric_guard = module.params['pn_fabric_guard']
    local_switching = module.params['pn_local_switching']
    lacp_priority = module.params['pn_lacp_priority']
    send_port = module.params['pn_send_port']
    port_mac_address = module.params['pn_port_mac_address']
    bw_bps = module.params['pn_bw_bps']

    # Building the CLI command string
    cli = pn_cli(module, switch)
    cli += ' port-config-' + mod_action
    if mod_action in ['modify']:
        if intf:
            cli += ' intf ' + intf
        if crc_check_enable:
            if crc_check_enable is True:
                cli += ' crc-check-enable '
            else:
                cli += ' crc-check-disable '
        if dscp_map:
            cli += ' dscp-map ' + dscp_map
        if autoneg:
            if autoneg is True:
                cli += ' autoneg '
            else:
                cli += ' no-autoneg '
        if speed:
            cli += ' speed ' + speed
        if port:
            cli += ' port ' + port
            if enable == True:
                cli += ' enable'
            else:
                cli += ' disable'
        if vxlan_termination:
            if vxlan_termination is True:
                cli += ' vxlan-termination '
            else:
                cli += ' no-vxlan-termination '
        if pause:
            if pause is True:
                cli += ' pause '
            else:
                cli += ' no-pause '
        if loopback:
            if loopback is True:
                cli += ' loopback '
            else:
                cli += ' no-loopback '
        if loop_vlans:
            cli += ' loop-vlans ' + loop_vlans
        if routing:
            if routing is True:
                cli += ' routing '
            else:
                cli += ' no-routing '
        if edge_switch:
            if edge_switch is True:
                cli += ' edge-switch '
            else:
                cli += ' no-edge-switch '
        if description:
            cli += ' description ' + description
        if host_enable:
            if host_enable is True:
                cli += ' host-enable '
            else:
                cli += ' host-disable '
        if allowed_tpid:
            cli += ' allowed-tpid ' + allowed_tpid
        if mirror_only:
            if mirror_only is True:
                cli += ' mirror-only '
            else:
                cli += ' no-mirror-receive-only '
        if reflect:
            if reflect is True:
                cli += ' reflect '
            else:
                cli += ' no-reflect '
        if jumbo:
            if jumbo is True:
                cli += ' jumbo '
            else:
                cli += ' no-jumbo '
        if egress_rate_limit:
            cli += ' egress-rate-limit ' + egress_rate_limit
        if eth_mode:
            cli += ' eth-mode ' + eth_mode
        if fabric_guard:
            if fabric_guard is True:
                cli += ' fabric-guard '
            else:
                cli += ' no-fabric-guard '
        if local_switching:
            if local_switching is True:
                cli += ' local-switching '
            else:
                cli += ' no-local-switching '
        if lacp_priority:
            cli += ' lacp-priority ' + lacp_priority
        if send_port:
            cli += ' send-port ' + send_port
        if port_mac_address:
            cli += ' port-mac-address ' + port_mac_address
        if bw_bps:
            cli += ' bw-bps ' + bw_bps

    run_cli(module, cli)

if __name__ == '__main__':
    main()
