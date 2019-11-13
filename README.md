# cisco-asa-acl-tester
Script for testing valid host-to-host ACL entries on Cisco ASA firewalls (software version 8.4 and later):
  
  1) Takes valid host-to-host ACL entries from the clipboard.
  2) Automatically finds the incoming interface and the name of the access-list configured on that interface.
  3) Tests a new ACL entry against existing ones.
  4) Automatically configures corresponding ACL entry to allow the traffic through the firewall
     (shows the ACL lines and asks for confirmation).

Input example:
access-list test-app extended permit tcp host 10.0.0.10 host 192.168.0.10 eq 443
access-list test-app extended permit udp host 10.0.0.15 host 192.168.0.10 eq 53
