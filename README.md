# ONeT Access

A routing/configuration tool that allows an Android phone running "EasyTether" to share its connection wirelessly
to other devices through the use of hostapd.

Designed with a minimalistic approach to run on Embedded Linux.

Build Requirements:
- clang
- make

Building:
- make

Client Requirements:
- hostapd
- dnsmasq

Running ONeT:
- "-h" : Help prompt
- "-g" : Generate default config
- "-s" : Start ONeT
- "-d" : Do not kill existing wireless processes (if running)
- "-w" : Not implemented

File Structure:

ONeT Access stores file in "/etc/ONeT/hotspot" within this directory you will find "config/" and "custom.ini"

custom.ini : Is used to configure the hotspot SSID, password, interface for WAN, and country.
config/ : contains the ".int" files used for LAN interface configuration of wireless or wired interfaces, supporting both with the given options.
