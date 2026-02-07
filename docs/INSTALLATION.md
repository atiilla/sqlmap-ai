# Installation

## Prerequisites

- Python 3.8+
- SQLMap (must be installed globally on your system)
- Internet connection (for cloud AI providers)
- 2GB+ RAM (for Ollama local models)

## Step 1: Install SQLMap

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

## Step 2: Install SQLMap AI

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

## Step 3: Configure AI Providers

Choose one or more AI providers to use:

### Option A: Groq (Recommended - Fastest)
1. Get a free API key from [https://console.groq.com](https://console.groq.com)
2. Add to your `.env` file:
```bash
GROQ_API_KEY=your_groq_api_key_here
```

### Option B: DeepSeek (Affordable)
1. Get an API key from [https://platform.deepseek.com](https://platform.deepseek.com)
2. Add to your `.env` file:
```bash
DEEPSEEK_API_KEY=your_deepseek_api_key_here
```

### Option C: OpenAI
1. Get an API key from [https://platform.openai.com](https://platform.openai.com)
2. Add to your `.env` file:
```bash
OPENAI_API_KEY=your_openai_api_key_here
```

### Option D: Anthropic (Claude)
1. Get an API key from [https://console.anthropic.com](https://console.anthropic.com)
2. Add to your `.env` file:
```bash
ANTHROPIC_API_KEY=your_anthropic_api_key_here
```

### Option E: Ollama (Local AI - Privacy Focused)
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

## Step 4: Run Configuration Wizard

```bash
# Interactive setup
sqlmap-ai --config-wizard
```

This will:
- Check your AI provider setup
- Let you select Ollama models (if using Ollama)
- Configure security settings
- Set up SQLMap options

## Step 5: Test Your Setup

```bash
# Check if everything is working
sqlmap-ai --check-providers

# List available Ollama models (if using Ollama)
sqlmap-ai --list-ollama-models
```

## AI Providers Comparison

| Provider | Setup | Speed | Privacy | Cost |
|----------|-------|-------|---------|------|
| **Groq** | API Key | Fastest | Cloud | Free tier available |
| **DeepSeek** | API Key | Fast | Cloud | Affordable |
| **OpenAI** | API Key | Fast | Cloud | Pay per use |
| **Anthropic** | API Key | Fast | Cloud | Pay per use |
| **Ollama** | Local install | Fast | Local | Free |
