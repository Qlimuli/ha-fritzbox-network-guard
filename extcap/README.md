# Wireshark Extcap – FRITZ!Box Packet Capture (from Host)

Ready-to-use **Wireshark external capture (extcap)** so you can capture live traffic **from your host machine**.

## Source

Based on [Rob--W/fritzbox-extcap-wireshark](https://github.com/Rob--W/fritzbox-extcap-wireshark).  
Uses the hidden AVM capture endpoint (`/cgi-bin/capture_notimeout`).

## Install on the Host

1. Find your Wireshark extcap path:
   ```bash
   tshark -G folders | grep -i extcap
   # or: Help → About Wireshark → Folders → Personal Extcap path
   ```
2. Copy the script:
   ```bash
   cp fritzbox-capture.sh ~/.local/lib/wireshark/extcap/
   chmod +x ~/.local/lib/wireshark/extcap/fritzbox-capture.sh
   ```
3. Restart Wireshark → interface **FRITZ!Box capture** appears.
4. Gear icon → set IP, interface (`1-lan`, `2-1`, …), and **SID**  
   (log into the FritzBox web UI and copy any URL containing `sid=…`).

## Interfaces (examples)

Visit `https://fritz.box/?lp=cap` while logged in for exact IDs on your model.

| ID     | Meaning              |
|--------|----------------------|
| 1-lan  | LAN bridge           |
| 2-1    | Internet / WAN       |
| 1-eth0…3 | Physical LAN ports |
| 4-133  | WLAN 2.4 GHz (ex.)   |
| 4-135  | WLAN 5 GHz (ex.)     |

## Relation to the Add-on

**FritzBox Network Guard 2.2+** can start the same capture **inside the container**, store PCAPs under `/data/captures`, run light analysis with `tshark`, and show results in the **Traffic** tab of the Ingress UI.

- Host Extcap → full Wireshark GUI on your desktop  
- Add-on capture → automated / always-on from HA  

## Companion

**[FRITZ!Portal](https://github.com/jayjojayson/FRITZ-Portal)** – rich live dashboard, topology, traffic charts.
