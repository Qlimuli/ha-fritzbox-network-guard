#!/bin/bash
# FritzBox Wireshark Extcap – wrapper / pointer
# Full maintained script: https://github.com/Rob--W/fritzbox-extcap-wireshark
# Install:
#   git clone https://github.com/Rob--W/fritzbox-extcap-wireshark.git
#   cp fritzbox-extcap-wireshark/fritzbox-capture.sh ~/.local/lib/wireshark/extcap/
#   chmod +x ~/.local/lib/wireshark/extcap/fritzbox-capture.sh
#
# This repository ships the documentation and the in-addon Python capture
# (packet_capture.py) that uses the same FritzBox endpoint.
echo "Please install the full extcap from https://github.com/Rob--W/fritzbox-extcap-wireshark" >&2
echo "See also the README.md in this folder." >&2
exit 1
