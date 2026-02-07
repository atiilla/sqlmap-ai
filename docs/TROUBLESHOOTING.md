# Troubleshooting

## Common Issues

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

## Getting Help

```bash
# Show all available commands
sqlmap-ai --help

# Show enhanced mode help
sqlmap-ai --enhanced --help

# Show simple mode help
sqlmap-ai --simple --help
```
