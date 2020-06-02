# Lab2 Privilege Escalation
- Lab2-1 Find the service may has misconfiguration
    - Hint: get-wmiobject win32_service | ?{$_.pathname -match "<mark>TODO</mark>"} | select Name, Pathname, State, ProcessID 
- Lab2-2 Expolit the misconfiguration to escalate privilege
    - Hint; createProcess() api has some properties when the input has space
- Lab2-3 Add a hidden account in local comoputer to achieve persistence
    - Get local system account from previous step
    - Manipulae SAM in registry
