# Lab2 Privilege Escalation
- Lab2-1 Find the service may has misconfiguration
    - Hint1: get-wmiobject win32_service | ?{$_.pathname -match "<mark>TODO</mark>"} | select Name, Pathname, State, ProcessID 
    - Hint2: get-acl
- Lab2-2 Expolit the misconfiguration to escalate privilege
    - Hint: createProcess() api has some properties when the input has space
    - Question: How to name and place the malicilus exe?
- Lab2-3 Add a hidden account in local comoputer to achieve persistence
    - Get a local system account from previous step
    - Manipulate SAM in registry
    - can’t see in net user or account management gui
![you can't see me](./ycm.jpg)
