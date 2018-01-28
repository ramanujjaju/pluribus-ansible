#!/usr/bin/python

def pn_cli(module, switch=None, username=None, password=None, switch_local=None):
    """
    Method to generate the cli portion to launch the Netvisor cli.
    :param module: The Ansible module to fetch username and password.
    :return: The cli string for further processing.
    """

    cli = '/usr/bin/cli --quiet -e --no-login-prompt '

    if username and password:
        cli += '--user "%s":"%s" ' % (username, password)
    if switch:
        cli += ' switch ' + switch
    if switch_local:
        cli += ' switch-local '

    return cli


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
    network_supernet = find_network_v6(address, mask_supernet)
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
