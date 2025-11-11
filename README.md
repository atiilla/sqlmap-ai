# SQLMap AI Assistant

An AI-powered wrapper around SQLMap that makes SQL injection testing more accessible and automated.

## Features

### Core Features
- **AI-Assisted Testing** - Intelligent vulnerability analysis and recommendations
- **Adaptive Testing** - Step-by-step testing that adapts to target responses
- **Enhanced HTML Reports** - Beautiful, detailed reports with vulnerability details
- **Parameter Targeting** - Test specific parameters with `-p` option (like original SQLMap)
- **WAF Bypass** - Automatic tamper script selection for firewall evasion
- **Database Enumeration** - Complete database, table, and column discovery
- **Request File Support** - Test from Burp Suite, ZAP, or browser captures

### AI Providers
- **Groq** - Fastest AI analysis (recommended)
- **OpenAI** - GPT-4 powered analysis
- **Anthropic Claude** - Advanced reasoning
- **Ollama** - Local, private AI (no cloud required)

### New in v2.0.5
- [x] **Parameter Selection** - Target specific parameters with `-p id,username`
- [x] **Enhanced Reports** - Detailed HTML reports with tables, columns, and payloads
- [x] **Global SQLMap** - Uses your system's SQLMap installation
- [x] **Bug Fixes** - Improved database tracking and report generation

<img src="sqlmap.gif"/>

## Quick Start

### Step 1: Install SQLMap (Prerequisite)

First, install SQLMap globally on your system:

```bash
# Kali/Debian/Ubuntu
sudo apt install sqlmap

# macOS
brew install sqlmap

# Or from source
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
sudo python setup.py install

# Verify installation
sqlmap --version
```

### Step 2: Install SQLMap AI

```bash
# Clone the repository
git clone https://github.com/atiilla/sqlmap-ai.git
cd sqlmap-ai

# Install the package
pip install -e .

# Or install from PyPI
pip install sqlmap-ai

# Run installation check (creates config files)
sqlmap-ai --install-check
```

### Step 3: Configure AI Providers

Choose one or more AI providers to use:

#### Option A: Groq (Recommended - Fastest)
1. Get a free API key from [https://console.groq.com](https://console.groq.com)
2. Add to your `.env` file:
```bash
GROQ_API_KEY=your_groq_api_key_here
```

#### Option B: OpenAI
1. Get an API key from [https://platform.openai.com](https://platform.openai.com)
2. Add to your `.env` file:
```bash
OPENAI_API_KEY=your_openai_api_key_here
```

#### Option C: Anthropic (Claude)
1. Get an API key from [https://console.anthropic.com](https://console.anthropic.com)
2. Add to your `.env` file:
```bash
ANTHROPIC_API_KEY=your_anthropic_api_key_here
```

#### Option D: Ollama (Local AI - Privacy Focused)
1. Install Ollama: [https://ollama.ai/download](https://ollama.ai/download)
2. Start Ollama service:
```bash
ollama serve
```
3. Download a model:
```bash
ollama pull llama3.2
```
4. Enable in your `.env` file:
```bash
ENABLE_OLLAMA=true
OLLAMA_MODEL=llama3.2
```

### Step 4: Run Configuration Wizard

```bash
# Interactive setup
sqlmap-ai --config-wizard
```

This will:
- Check your AI provider setup
- Let you select Ollama models (if using Ollama)
- Configure security settings
- Set up SQLMap options

### Step 5: Test Your Setup

```bash
# Check if everything is working
sqlmap-ai --check-providers

# List available Ollama models (if using Ollama)
sqlmap-ai --list-ollama-models
```

## Usage Examples

### Basic SQL Injection Test

```bash
# Test a vulnerable website
sqlmap-ai -u "http://example.com/page.php?id=1"

# Use specific AI provider
sqlmap-ai -u "http://example.com/page.php?id=1" --ai-provider groq
```

### HTTP Request File Testing (NEW!)

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

### Advanced Testing

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

### AI Provider Selection

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

### Parameter-Specific Testing

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

### Complete Testing Workflow

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
- Request file support (NEW!)
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

## AI Providers Comparison

| Provider | Setup | Speed | Privacy | Cost |
|----------|-------|-------|---------|------|
| **Groq** | API Key | Fastest | Cloud | Free tier available |
| **OpenAI** | API Key | Fast | Cloud | Pay per use |
| **Anthropic** | API Key | Fast | Cloud | Pay per use |
| **Ollama** | Local install | Fast | Local | Free |

## Configuration Files

### .env File
Created automatically by `sqlmap-ai --install-check`:

```bash
# AI Provider API Keys
GROQ_API_KEY=your_groq_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here

# Ollama Settings (if using local AI)
ENABLE_OLLAMA=false
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2

# Security Settings
MAX_REQUESTS_PER_MINUTE=60
SAFE_MODE=true
AUDIT_LOGGING=true
```

### config.yaml
Created automatically by `sqlmap-ai --config-wizard`:

```yaml
version: "2.0"
security:
  safe_mode: true
  max_requests_per_minute: 60
  audit_logging: true

sqlmap:
  default_timeout: 120
  default_risk: 1
  default_level: 1
  default_threads: 5

ui:
  show_banner: true
  interactive_mode: false
```

## Troubleshooting

### Common Issues

**1. "No AI providers available"**
- Check your `.env` file has correct API keys
- Run `sqlmap-ai --check-providers` to verify

**2. "Ollama not detected"**
- Make sure Ollama is running: `ollama serve`
- Check if models are installed: `ollama list`
- Verify `.env` has `ENABLE_OLLAMA=true`

**3. "SQLMap not found"**
- Install SQLMap globally using one of these methods:
  - **Kali/Debian/Ubuntu:** `sudo apt install sqlmap`
  - **macOS:** `brew install sqlmap`
  - **From source:** `git clone https://github.com/sqlmapproject/sqlmap.git && cd sqlmap && sudo python setup.py install`
- Verify installation: `sqlmap --version`

**4. "Configuration issues"**
- Run `sqlmap-ai --config-wizard` to fix setup
- Check `sqlmap-ai --validate-config` for issues

**5. "Request file not working"**
- Ensure request file has proper HTTP format
- Check that Host header is present
- Verify request file path is correct
- Try with `--simple` mode first: `sqlmap-ai --simple -r request.txt`

**6. "URL validation failed"**
- When using request files, the URL is automatically extracted
- Ensure request file contains valid HTTP request
- Check that the Host header matches the target domain

### Getting Help

```bash
# Show all available commands
sqlmap-ai --help

# Show enhanced mode help
sqlmap-ai --enhanced --help

# Show simple mode help
sqlmap-ai --simple --help
```

## Command-Line Options

### Target Specification
```bash
-u, --url URL              Target URL (e.g., "http://example.com/page?id=1")
-r, --request FILE         Load HTTP request from file (Burp/ZAP/Browser)
```

### Parameter Testing
```bash
-p, --param PARAMS         Test specific parameter(s) (comma-separated)
                          Examples: -p id | -p id,username,token
```

### Scanning Options
```bash
--adaptive                 Use adaptive step-by-step testing
--aggressive               Aggressive testing (risk=3, level=5)
--stealth                  Stealth mode (slower, more evasive)
--timeout SECONDS          Scan timeout in seconds (default: 120)
--threads NUM              Number of threads 1-20 (default: 5)
--risk LEVEL               Risk level 1-3 (default: 1)
--level LEVEL              Test level 1-5 (default: 1)
```

### AI Configuration
```bash
--ai-provider PROVIDER     AI provider: groq|openai|anthropic|ollama|auto
--disable-ai               Disable AI analysis
--ollama-model MODEL       Specific Ollama model to use
```

### WAF Evasion
```bash
--tamper SCRIPTS           Tamper scripts (comma-separated)
--auto-tamper              Auto-select tamper scripts based on WAF
--random-agent             Use random User-Agent
```

### Output Options
```bash
--output-dir DIR           Output directory for reports (default: reports)
--output-format FORMAT     Output format: html|json|text
--save-json                Save results as JSON
```

### Configuration
```bash
--config-wizard            Run interactive configuration wizard
--check-providers          Check AI provider availability
--list-ollama-models       List available Ollama models
--install-check            Check installation and create config files
```

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

### Ollama Model Selection

If using Ollama, you can select different models:

```bash
# List available models
sqlmap-ai --list-ollama-models

# Interactive model selection
sqlmap-ai --config-wizard
```

Popular models:
- **llama3.2** - Good general performance
- **codellama** - Specialized for code analysis
- **mistral** - Fast and efficient
- **qwen2.5** - Good reasoning capabilities

## Requirements

- Python 3.8+
- SQLMap (must be installed globally on your system)
  - Kali/Debian/Ubuntu: `sudo apt install sqlmap`
  - macOS: `brew install sqlmap`
  - From source: [github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)
- Internet connection (for cloud AI providers)
- 2GB+ RAM (for Ollama local models)

## License

This project is licensed under the MIT License.

## Disclaimer

This tool is intended for educational and ethical hacking purposes only. Always obtain permission before testing any system or application. The developers are not responsible for any misuse or damage caused by this tool.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=atiilla/sqlmap-ai&type=Date)](https://www.star-history.com/#atiilla/sqlmap-ai&Date) 