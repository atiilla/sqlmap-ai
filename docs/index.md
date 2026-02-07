# SQLMap AI Documentation

**AI-powered SQL injection testing — smarter scans, adaptive strategies, beautiful reports.**

---

## What is SQLMap AI?

SQLMap AI is an intelligent wrapper around [SQLMap](https://sqlmap.org/) that combines automated SQL injection testing with AI-powered analysis. It supports multiple AI providers and adapts its testing strategy based on target responses.

## Key Features

- **AI-Assisted Testing** — Intelligent vulnerability analysis and recommendations
- **Adaptive Testing** — Step-by-step testing that adapts to target responses
- **Enhanced HTML Reports** — Beautiful, detailed reports with vulnerability details
- **Parameter Targeting** — Test specific parameters with `-p` option
- **WAF Bypass** — Automatic tamper script selection for firewall evasion
- **Database Enumeration** — Complete database, table, and column discovery
- **Request File Support** — Test from Burp Suite, ZAP, or browser captures

## AI Providers

| Provider | Speed | Privacy | Cost |
|----------|-------|---------|------|
| **Groq** | Fastest | Cloud | Free tier available |
| **DeepSeek** | Fast | Cloud | Affordable |
| **OpenAI** | Fast | Cloud | Pay per use |
| **Anthropic** | Fast | Cloud | Pay per use |
| **Ollama** | Fast | Local | Free |

## Quick Start

```bash
# 1. Install SQLMap
sudo apt install sqlmap        # Debian/Ubuntu/Kali
brew install sqlmap             # macOS

# 2. Install SQLMap AI
pip install sqlmap-ai
sqlmap-ai --install-check

# 3. Set an API key (Groq is free & fastest)
echo "GROQ_API_KEY=your_key_here" >> .env

# 4. Run your first scan
sqlmap-ai -u "http://example.com/page.php?id=1"
```

See the [Installation Guide](INSTALLATION.md) for full setup instructions.

## Documentation

| Guide | Description |
|-------|-------------|
| [Installation](INSTALLATION.md) | Prerequisites, setup, AI provider configuration |
| [Usage Guide](USAGE.md) | Examples, testing modes, request files, workflows |
| [Configuration](CONFIGURATION.md) | `.env`, `config.yaml`, CLI options reference |
| [Troubleshooting](TROUBLESHOOTING.md) | Common issues and getting help |
| [Changelog](CHANGELOG.md) | Version history and release notes |

## Latest Release — v2.0.6

- **Private Network Scanning** — Local/private IP targets now allowed by default
- **Configurable Network Policy** — New `allow_private_networks` security setting
- **Improved Test Coverage** — Dedicated tests for private network validation

See the full [Changelog](CHANGELOG.md) for previous versions.

## Links

- [GitHub Repository](https://github.com/atiilla/sqlmap-ai)
- [Report Issues](https://github.com/atiilla/sqlmap-ai/issues)
- [PyPI Package](https://pypi.org/project/sqlmap-ai/)

---

*This tool is intended for educational and authorized security testing only. Always obtain permission before testing any system.*
