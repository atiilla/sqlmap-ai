# Usage

## Basic SQL Injection Test

```bash
# Test a vulnerable website
sqlmap-ai -u "http://example.com/page.php?id=1"

# Use specific AI provider
sqlmap-ai -u "http://example.com/page.php?id=1" --ai-provider groq
```

## HTTP Request File Testing

```bash
# Test using HTTP request capture file
sqlmap-ai -r request.txt

# Enhanced mode with request file and adaptive testing
sqlmap-ai --enhanced --adaptive -r request.txt

# With specific AI provider
sqlmap-ai --enhanced -r request.txt --ai-provider groq

# Simple mode with request file
sqlmap-ai --simple -r request.txt
```

**Request File Format:**
```http
POST /login.php HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

username=admin&password=test
```

**Creating Request Files:**

1. **From Browser Developer Tools:**
   - Open Developer Tools (F12)
   - Go to Network tab
   - Perform the action you want to test
   - Right-click the request → Copy → Copy as cURL
   - Convert cURL to HTTP format

2. **From Burp Suite:**
   - Intercept the request
   - Right-click → Save item
   - Save as .txt file

3. **From OWASP ZAP:**
   - Right-click request → Export → HTTP Message
   - Save as .txt file

**Supported Request Types:**
 - [x] GET requests with parameters
 - [x] POST requests with form data
 - [x] POST requests with JSON data
 - [x] Requests with cookies
 - [x] Requests with custom headers
 - [x] Multipart form data

## Advanced Testing

```bash
# Adaptive testing (recommended)
sqlmap-ai --enhanced --adaptive -u "http://example.com/page.php?id=1"

# Test specific parameter only
sqlmap-ai --enhanced -u "http://example.com/page.php?id=1&name=test" -p id

# Simple mode (basic SQLMap without AI)
sqlmap-ai --simple -u "http://example.com/page.php?id=1"

# Enhanced mode with custom options
sqlmap-ai --enhanced -u "http://example.com/page.php?id=1" --level 3 --risk 2

# Test with aggressive settings
sqlmap-ai --enhanced --aggressive -u "http://example.com/page.php?id=1"

# Stealth mode with slower, more evasive testing
sqlmap-ai --enhanced --stealth -u "http://example.com/page.php?id=1"
```

## AI Provider Selection

```bash
# Use Groq (fastest)
sqlmap-ai -u "http://example.com/page.php?id=1" --ai-provider groq

# Use Ollama (local, private)
sqlmap-ai -u "http://example.com/page.php?id=1" --ai-provider ollama

# Use OpenAI
sqlmap-ai -u "http://example.com/page.php?id=1" --ai-provider openai

# Auto-select best available
sqlmap-ai -u "http://example.com/page.php?id=1" --ai-provider auto
```

## Parameter-Specific Testing

Test only specific parameters to save time and focus your testing:

```bash
# Test only the 'id' parameter
sqlmap-ai --enhanced -u "http://example.com/page.php?id=1&name=test" -p id

# Test multiple specific parameters
sqlmap-ai --enhanced -u "http://example.com/login?user=admin&pass=123&token=abc" -p user,pass

# Test with request file and specific parameter
sqlmap-ai --enhanced -r request.txt -p username

# Adaptive testing on specific parameter
sqlmap-ai --enhanced --adaptive -r request.txt -p id
```

**Benefits:**
- **Faster Testing** - Skip irrelevant parameters
- **Focused Analysis** - Concentrate on known vulnerable parameters
- **Cost Efficient** - Reduce AI API calls for large forms

## Complete Testing Workflow

```bash
# 1. Basic scan with URL
sqlmap-ai --enhanced -u "http://example.com/page.php?id=1"

# 2. Test specific parameter only
sqlmap-ai --enhanced -u "http://example.com/page?id=1&name=test" -p id

# 3. Enhanced scan with request file
sqlmap-ai --enhanced --adaptive -r captured_request.txt

# 4. Advanced scan with custom options
sqlmap-ai --enhanced -r request.txt --level 4 --risk 3 --threads 10

# 5. Simple mode for quick testing
sqlmap-ai --simple -r request.txt --batch
```

## Testing Modes

### Enhanced Mode (Default)
Full AI-powered testing with advanced features:

```bash
# Basic enhanced scan
sqlmap-ai --enhanced -u "http://example.com/page.php?id=1"

# With request file
sqlmap-ai --enhanced -r request.txt

# Adaptive testing with AI analysis
sqlmap-ai --enhanced --adaptive -r request.txt --ai-provider groq
```

**Features:**
- AI-powered vulnerability analysis
- Adaptive testing strategies
- WAF evasion techniques
- **Beautiful HTML reports** with comprehensive details
- Risk assessment and remediation guidance
- Interactive CLI with progress tracking
- Multiple AI providers (Groq, OpenAI, Anthropic, Ollama)
- Advanced configuration management
- Request file support
- Parameter-specific testing with `-p` option

**Enhanced HTML Reports Include:**
- [x] **Vulnerability Details** - Complete parameter analysis with injection payloads
- [x] **Database Information** - All discovered databases with tables and columns
- [x] **Scan History** - Detailed step-by-step findings with sample payloads
- [x] **Risk Assessment** - Overall risk level and vulnerability counts
- [x] **AI Recommendations** - Smart suggestions for remediation
- [x] **Interactive Charts** - Visual representation of scan results
- [x] **Export Ready** - Professional format for security reports

### Simple Mode
Basic SQL injection testing without AI features:

```bash
# Basic simple scan
sqlmap-ai --simple -u "http://example.com/page.php?id=1"

# With request file
sqlmap-ai --simple -r request.txt

# Quick batch mode
sqlmap-ai --simple -r request.txt --batch
```

**Features:**
- Basic SQL injection detection
- Standard SQLMap functionality
- Minimal dependencies
- Fast execution
- Request file support
- Simple text output
- Basic result saving

### Adaptive Mode
Intelligent step-by-step testing that adapts to the target:

```bash
# Full adaptive testing
sqlmap-ai --enhanced --adaptive -r request.txt

# With specific AI provider
sqlmap-ai --enhanced --adaptive -r request.txt --ai-provider groq
```

**Adaptive Steps:**
1. **Initial Assessment** - Quick vulnerability check
   - Tests for SQL injection with basic techniques
   - Identifies vulnerable parameters
   - Discovers initial database information

2. **DBMS Identification** - Detect specific database type
   - Identifies MySQL, PostgreSQL, Oracle, MSSQL, etc.
   - Enables database-specific attack optimization
   - Detects WAF/IPS presence

3. **Enhanced Database Testing** - Deep database enumeration
   - Enumerates all databases and tables
   - Extracts table structures and column names
   - Adapts based on discovered schema

4. **Data Extraction** - Extract sensitive information
   - Dumps data from identified tables
   - Targets high-value tables (users, credentials, etc.)
   - Uses optimized extraction techniques

5. **Enhanced Testing** - Aggressive vulnerability testing
   - Increases risk and level settings
   - Tests for advanced injection types
   - Attempts privilege escalation techniques

6. **Alternative Testing** - Test additional attack vectors
   - POST parameters and request body
   - Cookies and session data
   - HTTP headers (User-Agent, Referer, etc.)

## Advanced Features

### Adaptive Testing Mode
Automatically adapts testing strategy based on target response and discovered information:

```bash
# Enable adaptive mode
sqlmap-ai --enhanced --adaptive -u "http://example.com/page.php?id=1"

# With request file
sqlmap-ai --enhanced --adaptive -r request.txt

# With specific parameter
sqlmap-ai --enhanced --adaptive -r request.txt -p id
```

**How Adaptive Testing Works:**

The adaptive engine intelligently sequences through 6 testing phases, adjusting strategy based on what it discovers:

1. **Initial Assessment** - Quick vulnerability identification
2. **DBMS Identification** - Database fingerprinting and WAF detection
3. **Enhanced Database Testing** - Complete schema enumeration
4. **Data Extraction** - Targeted data dumping from sensitive tables
5. **Enhanced Testing** - Aggressive techniques if databases found
6. **Alternative Testing** - Additional attack vectors (POST, cookies, headers)

Each step builds on previous discoveries, ensuring efficient and thorough testing while minimizing unnecessary requests.
