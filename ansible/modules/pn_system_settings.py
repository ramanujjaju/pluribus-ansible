#!/usr/bin/python
""" PN CLI system-settings-modify """
#
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
#

import shlex
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pn_nvos import pn_cli

DOCUMENTATION = """
---
module: pn_system_settings
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to modify system-settings.
description:
  - C(modify): update system settings
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - system-settings configuration command.
    required: true
    choices: ['modify']
    type: str
  pn_lldp:
    description:
      - LLDP
    required: false
    type: bool
  pn_optimize_arps:
    description:
      - enable ARP optimization
    required: false
    type: bool
  pn_block_loops:
    description:
      - enable loop blocking
    required: false
    type: bool
  pn_manage_broadcast:
    description:
      - enable broadcast management
    required: false
    type: bool
  pn_reactivate_mac:
    description:
      - enable reactivation of aged out mac entries
    required: false
    type: bool
  pn_policy_based_routing:
    description:
      - enable policy based routing
    required: false
    type: bool
  pn_reactivate_vxlan_tunnel_mac:
    description:
      - enable reactivation of mac entries over vxlan tunnels
    required: false
    type: bool
  pn_optimize_nd:
    description:
      - enable ND optimization
    required: false
    type: bool
  pn_use_igmp_snoop_l2:
    description:
      - Use L2/L3 tables for IGMP Snooping
    required: false
    type: bool
  pn_manage_unknown_unicast:
    description:
      - enable unknown unicast management
    required: false
    type: bool
  pn_usb_port:
    description:
      - usb port
    required: false
    type: bool
  pn_cpu_class_enable:
    description:
      - cpu class enable
    required: false
    type: bool
  pn_source_mac_miss:
    description:
      - control unknown source mac learn behavior
    required: false
    choices: ['to-cpu', 'copy-to-cpu']
  pn_pfc_buffer_limit:
    description:
      - % of maximum buffers allowed for PFC
    required: false
    type: str
  pn_cluster_active_active_routing:
    description:
      - active-active routing on a cluster
    required: false
    type: bool
  pn_auto_trunk:
    description:
      - enable auto trunking
    required: false
    type: bool
  pn_vle_tracking_timeout:
    description:
      - vle tracking timeout
    required: false
    type: str
  pn_auto_host_bundle:
    description:
      - enable auto host bundling
    required: false
    type: bool
  pn_optimize_datapath:
    description:
      - Datapath optimization for cluster, fabric and data communication
    required: false
    choices: ['disable', 'cluster-only', 'all']
  pn_routing_over_vlags:
    description:
      - enable/disable routing to vlags from cluster links
    required: false
    type: bool
"""

EXAMPLES = """
- name: Modify system settings
  pn_system_setings:
    pn_action: "modify"
    pn_policy_based_routing: True
    pn_auto_trunk: False
    pn_optimize_arps: True
    pn_optimize_nd: True
    pn_lldp: True
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the system-settings command.
  returned: always
  type: list
stderr:
  description: set of error responses from the system-settings command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
"""

RESTART_STR = "nvOSd must be restarted for this setting to take effect"


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
            msg="System settings %s operation failed" % action,
            changed=False
        )
    else:
        return out


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliusername=dict(required=False, type='str', no_log=True),
            pn_clipassword=dict(required=False, type='str', no_log=True),
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str', choices=['modify']),
            pn_lldp=dict(required=False, type='bool'),
            pn_optimize_arps=dict(required=False, type='bool'),
            pn_block_loops=dict(required=False, type='bool'),
            pn_manage_broadcast=dict(required=False, type='bool'),
            pn_reactivate_mac=dict(required=False, type='bool'),
            pn_policy_based_routing=dict(required=False, type='bool'),
            pn_reactivate_vxlan_tunnel_mac=dict(required=False, type='bool'),
            pn_optimize_nd=dict(required=False, type='bool'),
            pn_use_igmp_snoop_l2=dict(required=False, type='bool'),
            pn_manage_unknown_unicast=dict(required=False, type='bool'),
            pn_usb_port=dict(required=False, type='bool'),
            pn_cpu_class_enable=dict(required=False, type='bool'),
            pn_source_mac_miss=dict(required=False, type='str', choices=['to-cpu', 'copy-to-cpu']),
            pn_pfc_buffer_limit=dict(required=False, type='str'),
            pn_cluster_active_active_routing=dict(required=False, type='bool'),
            pn_auto_trunk=dict(required=False, type='bool'),
            pn_vle_tracking_timeout=dict(required=False, type='str'),
            pn_auto_host_bundle=dict(required=False, type='bool'),
            pn_optimize_datapath=dict(required=False, type='str', choices=['disable', 'cluster-only', 'all']),
            pn_routing_over_vlags=dict(required=False, type='bool'),
        )
    )

    # Accessing the arguments
    switch = module.params['pn_cliswitch']
    username = module.params['pn_cliusername']
    password = module.params['pn_clipassword']
    action = module.params['pn_action']
    command = 'system-settings-' + action
    lldp = module.params['pn_lldp']
    optimize_arps = module.params['pn_optimize_arps']
    block_loops = module.params['pn_block_loops']
    manage_broadcast = module.params['pn_manage_broadcast']
    reactivate_mac = module.params['pn_reactivate_mac']
    policy_based_routing = module.params['pn_policy_based_routing']
    reactivate_vxlan_tunnel_mac = module.params['pn_reactivate_vxlan_tunnel_mac']
    optimize_nd = module.params['pn_optimize_nd']
    use_igmp_snoop_l2 = module.params['pn_use_igmp_snoop_l2']
    manage_unknown_unicast = module.params['pn_manage_unknown_unicast']
    usb_port = module.params['pn_usb_port']
    cpu_class_enable = module.params['pn_cpu_class_enable']
    source_mac_miss = module.params['pn_source_mac_miss']
    pfc_buffer_limit = module.params['pn_pfc_buffer_limit']
    cluster_active_active_routing = module.params['pn_cluster_active_active_routing']
    auto_trunk = module.params['pn_auto_trunk']
    vle_tracking_timeout = module.params['pn_vle_tracking_timeout']
    auto_host_bundle = module.params['pn_auto_host_bundle']
    optimize_datapath = module.params['pn_optimize_datapath']
    routing_over_vlags = module.params['pn_routing_over_vlags']

    # Building the CLI command string
    cli = pn_cli(module, switch)
    cli += " " + command

    if lldp:
        if lldp is True:
            cli += ' lldp '
        else:
            cli += ' no-lldp '
    if optimize_arps:
        if optimize_arps is True:
            cli += ' optimize-arps '
        else:
            cli += ' no-optimize-arps '
    if block_loops:
        if block_loops is True:
            cli += ' block-loops '
        else:
            cli += ' no-block-loops '
    if manage_broadcast:
        if manage_broadcast is True:
            cli += ' manage-broadcast '
        else:
            cli += ' no-manage-broadcast '
    if reactivate_mac:
        if reactivate_mac is True:
            cli += ' reactivate-mac '
        else:
            cli += ' no-reactivate-mac '
    if policy_based_routing:
        if policy_based_routing is True:
            cli += ' policy-based-routing '
        else:
            cli += ' no-policy-based-routing '
    if reactivate_vxlan_tunnel_mac:
        if reactivate_vxlan_tunnel_mac is True:
            cli += ' reactivate-vxlan-tunnel-mac '
        else:
            cli += ' no-reactivate-vxlan-tunnel-mac '
    if optimize_nd:
        if optimize_nd is True:
            cli += ' optimize-nd '
        else:
            cli += ' no-optimize-nd '
    if use_igmp_snoop_l2:
        if use_igmp_snoop_l2 is True:
            cli += ' use-igmp-snoop-l2 '
        else:
            cli += ' use-igmp-snoop-l3 '
    if manage_unknown_unicast:
        if manage_unknown_unicast is True:
            cli += ' manage-unknown-unicast '
        else:
            cli += ' no-manage-unknown-unicast '
    if usb_port:
        if usb_port is True:
            cli += ' usb-port '
        else:
            cli += ' no-usb-port '
    if cpu_class_enable:
        if cpu_class_enable is True:
            cli += ' cpu-class-enable '
        else:
            cli += ' no-cpu-class-enable '
    if source_mac_miss:
        cli += ' source-mac-miss ' + source_mac_miss
    if pfc_buffer_limit:
        cli += ' pfc-buffer-limit ' + pfc_buffer_limit
    if cluster_active_active_routing:
        if cluster_active_active_routing is True:
            cli += ' cluster-active-active-routing '
        else:
            cli += ' no-cluster-active-active-routing '
    if auto_trunk:
        if auto_trunk is True:
            cli += ' auto-trunk '
        else:
            cli += ' no-auto-trunk '
    if vle_tracking_timeout:
        cli += ' vle-tracking-timeout ' + vle_tracking_timeout
    if auto_host_bundle:
        if auto_host_bundle is True:
            cli += ' auto-host-bundle '
        else:
            cli += ' no-auto-host-bundle '
    if optimize_datapath:
        cli += ' optimize-datapath ' + optimize_datapath
    if routing_over_vlags:
        if routing_over_vlags is True:
            cli += ' routing-over-vlags '
        else:
            cli += ' no-routing-over-vlags '

    aggr_cli = cli
    out = run_cli(module, cli)
    aggr_out = out

    if out is not None:
        if RESTART_STR in out:
            cli = pn_cli(module, switch, username, password)
            cli += ' nvos-restart '
            aggr_cli += ' and ' + cli
            out = run_cli(module, cli)
            if out is not None:
                aggr_out += out
        module.exit_json(
            command=aggr_cli,
            stdout=aggr_out.strip(),
            msg="system-settings %s operation completed" % action,
            changed=True
        )
    else:
        module.exit_json(
            command=aggr_cli,
            stdout=aggr_out.strip(),
            msg="system-settings %s operation completed" % action,
            changed=True
        )

if __name__ == '__main__':
    main()
