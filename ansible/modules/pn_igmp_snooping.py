#!/usr/bin/python
""" PN CLI igmp-snooping-modify """

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
module: pn_igmp_snooping
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to modify igmp-snooping.
description:
  - C(modify): modify Internet Group Management Protocol (IGMP) snooping
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - igmp-snooping configuration command.
    required: true
    choices: ['modify']
    type: str
  pn_enable:
    description:
      - enable or disable IGMP snooping
    required: false
    type: bool
  pn_igmpv2_vlans:
    description:
      - VLANs on which to use IGMPv2 protocol
    required: false
    type: str
  pn_igmpv3_vlans:
    description:
      - VLANs on which to use IGMPv3 protocol
    required: false
    type: str
  pn_enable_vlans:
    description:
      - enable per VLAN IGMP snooping
    required: false
    type: str
  pn_vxlan:
    description:
      - enable or disable IGMP snooping on vxlans
    required: false
    type: bool
  pn_scope:
    description:
      - IGMP snooping scope - fabric or local
    required: false
    choices: ['local', 'fabric']
  pn_no_snoop_linklocal_vlans:
    description:
      - Remove snooping of link-local groups(224.0.0.0/24) on these vlans
    required: false
    type: str
  pn_snoop_linklocal_vlans:
    description:
      - Allow snooping of link-local groups(224.0.0.0/24) on these vlans
    required: false
    type: str
"""

EXAMPLES = """
- name: Modify igmp snooping
  pn_igmp_snooping:
    pn_action: 'modify'
    pn_enable: True
    pn_vxlan: True
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the igmp-snooping command.
  returned: always
  type: list
stderr:
  description: set of error responses from the igmp-snooping command.
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
            msg="igmp-snooping %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="igmp-snooping %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="igmp-snooping %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str', choices=['modify']),
            pn_enable=dict(required=False, type='bool'),
            pn_igmpv2_vlans=dict(required=False, type='str'),
            pn_igmpv3_vlans=dict(required=False, type='str'),
            pn_enable_vlans=dict(required=False, type='str'),
            pn_vxlan=dict(required=False, type='bool'),
            pn_scope=dict(required=False, type='str', choices=['local', 'fabric']),
            pn_no_snoop_linklocal_vlans=dict(required=False, type='str'),
            pn_snoop_linklocal_vlans=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    switch = module.params['pn_cliswitch']
    enable = module.params['pn_enable']
    igmpv2_vlans = module.params['pn_igmpv2_vlans']
    igmpv3_vlans = module.params['pn_igmpv3_vlans']
    enable_vlans = module.params['pn_enable_vlans']
    vxlan = module.params['pn_vxlan']
    scope = module.params['pn_scope']
    no_snoop_linklocal_vlans = module.params['pn_no_snoop_linklocal_vlans']
    snoop_linklocal_vlans = module.params['pn_snoop_linklocal_vlans']

    # Building the CLI command string
    cli = pn_cli(module, switch)
    cli += 'igmp-snooping-' + action
    if action in ['modify']:
        if enable:
            if enable is True:
                cli += ' enable '
            else:
                cli += ' disable '
        if igmpv2_vlans:
            cli += ' igmpv2-vlans ' + igmpv2_vlans
        if igmpv3_vlans:
            cli += ' igmpv3-vlans ' + igmpv3_vlans
        if enable_vlans:
            cli += ' enable-vlans ' + enable_vlans
        if vxlan:
            if vxlan is True:
                cli += ' vxlan '
            if vxlan is False:
                cli += ' no-vxlan '
        if scope:
            cli += ' scope ' + scope
        if no_snoop_linklocal_vlans:
            cli += ' no-snoop-linklocal-vlans ' + no_snoop_linklocal_vlans
        if snoop_linklocal_vlans:
            cli += ' snoop-linklocal-vlans ' + snoop_linklocal_vlans

    run_cli(module, cli)

if __name__ == '__main__':
    main()
