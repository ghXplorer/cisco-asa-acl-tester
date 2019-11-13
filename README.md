# cisco-asa-acl-tester
Script for testing valid host-to-host ACL entries on Cisco ASA firewalls (software version 8.4 and later):

  1) Automatically finds the incoming interface and the access-list configured on that interface.
  2) Tests a new ACL entry against existing ones.
  3) Automatically configures corresponding ACL entry to allow the traffic through the firewall.
