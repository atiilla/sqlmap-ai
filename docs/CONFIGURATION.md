# Configuration

## .env File

Created automatically by `sqlmap-ai --install-check`:

```bash
# AI Provider API Keys
GROQ_API_KEY=your_groq_api_key_here
DEEPSEEK_API_KEY=your_deepseek_api_key_here
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

## config.yaml

Created automatically by `sqlmap-ai --config-wizard`:

```yaml
version: "2.0"
security:
  safe_mode: true
  max_requests_per_minute: 60
  audit_logging: true
  allow_private_networks: true  # Set to false to block local/private IP targets

sqlmap:
  default_timeout: 120
  default_risk: 1
  default_level: 1
  default_threads: 5

ui:
  show_banner: true
  interactive_mode: false
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
--ai-provider PROVIDER     AI provider: groq|deepseek|openai|anthropic|ollama|auto
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

### Configuration Commands
```bash
--config-wizard            Run interactive configuration wizard
--check-providers          Check AI provider availability
--list-ollama-models       List available Ollama models
--install-check            Check installation and create config files
--validate-config          Validate current configuration
```
