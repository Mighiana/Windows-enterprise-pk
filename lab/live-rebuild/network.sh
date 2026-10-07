#!/usr/bin/env bash
# Host-only bridge for the two lab VMs. No NAT or default route is configured for the guests,
# so the lab cannot reach the internet. Re-run after every host reboot (taps are not persistent).
set -euo pipefail
sudo ip link show pkibr0 >/dev/null 2>&1 || sudo ip link add pkibr0 type bridge
sudo ip addr replace 192.168.77.1/24 dev pkibr0
for tap in pki-srv pki-cli; do
  sudo ip link show "$tap" >/dev/null 2>&1 || sudo ip tuntap add dev "$tap" mode tap user "$(id -un)"
  sudo ip link set "$tap" master pkibr0
  sudo ip link set "$tap" up
done
sudo ip link set pkibr0 up
ip -br addr show pkibr0
