# Basic Hunting
[TOC]
## User and Computer Hunting

1. Find the user student0
    - ldap.filter = "(samaccountname=student0)"
1. Find all computers
    - ldap.filter = "(objectclass=computer))"
1. Find all groups
    - ldap.filter = "(objectclass=class))"
1. Find all OU
    - ldap.filter = "(objectclass=organizationalUnit)"
1. Find the groups you belong to
    - whoami /all
1. Find the groups the user "intern" belong to
    - ldap.filter = "(&(objectclass=group)(member=cn=student0,ou=student,dc=hackschool,dc=com))"
1. Find the members in the OU "student"
    - you can not use the target OU as part of the filter, the target OU should be specified as part of the query scope
    - OU's are scope objects
    - change the searchroot to OU, and search for user
    - searchroot = "LDAP://ou=student,DC=hackschool,DC=com"
    - $ldap.filter = "(objectclass=user)"
1. Find the members in the group "student"
    - ldap.filter = "((memberOf:1.2.840.113556.1.4.1941:=cn=student,ou=student,dc=hackschool,dc=com)"
1. Find all domain controller
    - ldap.filter = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
1. Find Domain Admins
1. Find all the members of "Domain Admins" 
    - ldap.filter = "(admincount=1)"
    - The adminCount attribute is found on user objects in Active Directory. This is a very simple attribute. If the value is \<not set\> or 0 then the user is not protected by the SD Propagation. If the value of adminCount is set to 1 that means the user has, or has been a member of a ==protected group==. The value can be seen in ADUC or ADSIEdit or LDP. Below is the attribute viewed via ADUC.
1. Find at least a user whose password never expire
    - ldap.filter = "(useraccountcontrol:1.2.840.113556.1.4.803:=65536)"
1. Find the users whose password has not been changed for 3 month

---
## SPN hunting
1. Find MSSQL server
    - setspn -q */:1433 
    - setspn -q MSSQL*/*
    - ldap.filter = "(servicePrincipalName=MSSQL*)"
1. Find the user with delegation 
    - ldap.filter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
1. Find the computer with contrained delegation 
1. Find the user with uncontrained delegation 
1. Find the computer with uncontrained delegation 

---
## User and Computer mapping
1. Find all local groups of Domain controller
    - NetSMBEnumeration
    - 
1. Find the members of local group "POC"
    - 
1. Find all the logged User on the computer in the OU "student"

---
## ACL and Group Policy 
1. Find the policy applied to your computer
1. Enumerate all group policy
1. Find who are applied GPO "test"
1. Find who has the right to edit the OU "student" 1. Find who can change the password of "student0"
