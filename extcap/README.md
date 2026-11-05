# Wireshark Extcap – FRITZ!Box Packet Capture (from Host)

This folder contains a ready-to-use **Wireshark external capture (extcap)** plugin so you can capture live traffic **from your host machine** (not only inside the Home Assistant add-on).

## Source

Based on [Rob--W/fritzbox-extcap-wireshark](https://github.com/Rob--W/fritzbox-extcap-wireshark).
The script uses the hidden AVM capture endpoint that many community tools rely on.

## Install on the Host

1. Find your Wireshark extcap path:
   ```bash
   tshark -G folders | grep -i extcap
   # or in Wireshark: Help → About Wireshark → Folders → Personal Extcap path
   ```
2. Copy the script:
   ```bash
   cp fritzbox-capture.sh ~/.local/lib/wireshark/extcap/
   chmod +x ~/.local/lib/wireshark/extcap/fritzbox-capture.sh
   ```
3. Restart Wireshark.
4. In the interface list you should see **FRITZ!Box capture**.
5. Click the gear icon, set:
   - FRITZ!Box IP (e.g. `192.168.178.1` or `fritz.box`)
   - Interface (e.g. `1-lan`, `2-1` for Internet, WLAN interfaces …)
   - **SID**: log into the FRITZ!Box web UI and copy any URL that contains `sid=…` (safer than storing the admin password in Wireshark)

## Interfaces (examples)

Visit `https://fritz.box/?lp=cap` while logged in to see the exact buttons / interface IDs for your model.

| ID       | Typical meaning          |
|----------|--------------------------|
| 1-lan    | LAN bridge               |
| 2-1      | Internet / WAN           |
| 1-eth0…3 | Physical LAN ports       |
| 4-133    | WLAN 2.4 GHz (example)   |
| 4-135    | WLAN 5 GHz (example)     |

## Relation to the Add-on

The Home Assistant add-on **FritzBox Network Guard** (v2.2+) can also start the same kind of capture **inside the container**, store PCAPs under `/data/captures`, run light analysis with `tshark`, and offer download + visualisation in the Ingress UI.

Use the host-side extcap when you want the full Wireshark GUI and filters on your desktop.  
Use the add-on capture when you want automated / always-on monitoring from HA without a permanent desktop session.

## Companion

For a rich real-time dashboard, device topology, traffic charts and convenient host management we recommend installing the separate add-on:

**[FRITZ!Portal](https://github.com/jayjojayson/FRITZ-Portal)** by jayjojayson.

Both add-ons work well side-by-side (this one focuses on security + packet capture, FRITZ!Portal on UX and live overview).
