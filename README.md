perl-check_fortigate_vpn
========================

This is a slight fork of the check_fortigate_vpn plugin found on the Nagios Exchange
http://exchange.nagios.org/directory/Plugins/Hardware/Network-Gear/Fortinet/Check-Fortigate-VPN-sessions/details

If anyone knows if the upstream auther has a repo with this check, please let me know and I'll open a pull request with my changes back upstream!

The only change made to the plugin at the moment is the addition of vdom's to the output during an error. 

Example output: 

```Shell
Fortinet: CRITICAL, Active SSL-VPN Connections/Tunnels: 0/0, IPSEC Tunnels: Configured/Active: 6/4 , cc1afba5-0 down on vdom Amazon_VPC, cc1afba5-1 down on vdom Amazon_VPC
```

