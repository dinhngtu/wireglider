#!/bin/sh

#ethtool -K eno1 rx-gro-list off rx-udp-gro-forwarding on
ethtool -K ibp8s0 rx-gro-list off rx-udp-gro-forwarding on
ethtool -K wg0 rx-gro-list off rx-udp-gro-forwarding on
#ip link set wg0 mtu 1420
ip link set wg0 mtu 1964

#wg set wg0 peer XXmnRm3crIM5cU92d1GA7l5sKzU+wosKfeWAYq1edCY= endpoint 192.168.0.3:51820 allowed-ips 10.77.44.2/32
wg set wg0 peer XXmnRm3crIM5cU92d1GA7l5sKzU+wosKfeWAYq1edCY= endpoint 10.88.77.3:51820 allowed-ips 10.77.44.2/32
#wg set wg0 peer 0kZFZAJSwoY5iVCE910ILzNQBBPo5WyewKcD+LnzZGs= endpoint 192.168.88.177:51820 allowed-ips 10.77.44.99/32

echo Configure OK
