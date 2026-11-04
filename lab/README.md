# Lab setup
Isolated libvirt network `nea-lab` (10.0.4.0/24, no forwarding, no internet).

1. `./setup.sh` defines and starts the network and DHCP reservations.
2. Metasploitable 2 (Rapid7, SourceForge) -> qcow2 read-only base; overlays meta2-a, meta2-b.
3. Snapshot `clean` per VM; revert between test runs.

Disk images and ISOs are not stored in this repo.
