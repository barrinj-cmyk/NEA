#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
virsh net-define nea-lab.xml
virsh net-start nea-lab
virsh net-autostart nea-lab
virsh net-update nea-lab add ip-dhcp-host "<host mac='52:54:00:00:04:11' name='meta2-a' ip='10.0.4.11'/>" --live --config
virsh net-update nea-lab add ip-dhcp-host "<host mac='52:54:00:00:04:12' name='meta2-b' ip='10.0.4.12'/>" --live --config
