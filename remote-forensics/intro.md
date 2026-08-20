# Remote Forensics Test

This is a temporary two-host network-isolation prototype.

Use the `controlplane` terminal only as the examination workstation. The target host is `172.30.2.2` (`node01`).

For this prototype, verify only that the target responds over the network, exposes the test HTTP service on TCP/8080, and no longer allows the default root SSH shortcut.
