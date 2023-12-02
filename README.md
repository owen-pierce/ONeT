# ONeT Access

A routing/configuration tool for allowing an Android phone running "EasyTether" to share its connection wirelessly
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
