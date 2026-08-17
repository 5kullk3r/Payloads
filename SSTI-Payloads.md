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

}

