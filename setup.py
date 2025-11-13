#!/usr/bin/env python3

import os
import sys
import subprocess
from pathlib import Path
from setuptools import setup, find_packages

# Read the README file
def read_readme():
    readme_path = Path(__file__).parent / "README.md"
    if readme_path.exists():
        return readme_path.read_text(encoding="utf-8")
    return "AI-powered SQL injection testing tool"

# Read requirements from pyproject.toml
def get_requirements():
    
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib
    
    pyproject_path = Path(__file__).parent / "pyproject.toml"
    if pyproject_path.exists():
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
            return data.get("project", {}).get("dependencies", [])
    return []

def install_sqlmap():
    
    try:
        # Check if sqlmap is already installed
        result = subprocess.run(
            ["sqlmap", "--version"], 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        if result.returncode == 0:
            print("✓ SQLMap is already installed")
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
        pass
    
    print("📦 Installing SQLMap...")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "sqlmap"],
            check=True,
            capture_output=True,
            text=True
        )
        print("✓ SQLMap installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"X Failed to install SQLMap: {e}")
        print("Please install SQLMap manually: pip install sqlmap")
        return False

def create_env_template():
    
    # Use current working directory instead of project root
    env_file = Path.cwd() / ".env"
    if env_file.exists():
        print("✓ .env file already exists")
        return True
    
    print("📝 Creating .env template...")
    
    env_content = """# SQLMap AI Configuration
# Copy this to .env file and fill in your API keys

# AI Provider API Keys
GROQ_API_KEY=your_groq_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here

# Optional: Enable Ollama (lightweight local LLM)
ENABLE_OLLAMA=false
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2

# Optional: Enable local LLM (requires more resources)
ENABLE_LOCAL_LLM=false
LOCAL_MODEL=microsoft/DialoGPT-medium

# Security Settings
MAX_REQUESTS_PER_MINUTE=60
SAFE_MODE=true
AUDIT_LOGGING=true

# Reporting Settings
ENABLE_PDF=true
ENABLE_HTML=true
ENABLE_JSON=true

# SQLMap Settings
SQLMAP_PATH=sqlmap
DEFAULT_TIMEOUT=300
"""
    
    try:
        with open(env_file, 'w') as f:
            f.write(env_content)
        print("✓ .env template created")
        print("  Please edit .env file and add your API keys")
        return True
    except Exception as e:
        print(f"X Failed to create .env template: {e}")
        return False

def setup_directories():
    
    print("📁 Setting up directories...")
    
    directories = [
        Path.cwd() / "reports",
        Path.cwd() / "logs",
        Path.cwd() / "config",
    ]
    
    try:
        for directory in directories:
            directory.mkdir(exist_ok=True)
        print("✓ Directories created")
        return True
    except Exception as e:
        print(f"X Failed to create directories: {e}")
        return False

def run_post_install():
    
    print("\nRunning post-installation tasks...")
    
    success = True
    
    # Install SQLMap
    if not install_sqlmap():
        success = False
    
    # Create .env template
    if not create_env_template():
        success = False
    
    # Setup directories
    if not setup_directories():
        success = False
    
    if success:
        print("\nInstallation completed successfully!")
        print("\nNext steps:")
        print("1. Edit .env file and add your API keys")
        print("2. Run: sqlmap-ai --config-wizard")
        print("3. Run: sqlmap-ai --help")
    else:
        print("\n⚠️ Installation completed with issues")
        print("Please resolve the issues above before using SQLMap AI")
    
    return success

# Main setup configuration
if __name__ == "__main__":
    # Run post-installation tasks after setup
    if "install" in sys.argv or "develop" in sys.argv:
        # Run setup first
        setup(
            name="sqlmap-ai",
            version="2.0.7",
            description="AI-powered SQL injection testing tool with multiple AI providers",
            long_description=read_readme(),
            long_description_content_type="text/markdown",
            author="Atilla",
            author_email="attilla@tuta.io",
            url="https://github.com/atiilla/sqlmap-ai",
            packages=find_packages(include=["sqlmap_ai*", "utils*"]),
            include_package_data=True,
            install_requires=get_requirements(),
            extras_require={
                "dev": [
                    "pytest>=7.0.0",
                    "pytest-asyncio>=0.21.0",
                    "black>=23.0.0",
                    "flake8>=6.0.0",
                    "mypy>=1.0.0",
                ],
                "local-llm": [
                    "transformers>=4.35.0",
                    "torch>=2.1.0",
                ],
                "reporting": [
                    "plotly>=5.0.0",
                    "pandas>=2.0.0",
                ],
                "all": [
                    "sqlmap-ai[dev,local-llm,reporting]",
                ],
            },
            entry_points={
                "console_scripts": [
                    "sqlmap-ai=sqlmap_ai.cli:main",
                    "sqlmapai=sqlmap_ai.cli:main",
                ],
            },
            python_requires=">=3.8",
            classifiers=[
                "Development Status :: 4 - Beta",
                "Intended Audience :: Information Technology",
                "Intended Audience :: System Administrators",
                "License :: OSI Approved :: MIT License",
                "Operating System :: OS Independent",
                "Programming Language :: Python :: 3",
                "Programming Language :: Python :: 3.8",
                "Programming Language :: Python :: 3.9",
                "Programming Language :: Python :: 3.10",
                "Programming Language :: Python :: 3.11",
                "Programming Language :: Python :: 3.12",
                "Topic :: Security",
                "Topic :: System :: Systems Administration",
                "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
                "Topic :: Software Development :: Testing",
            ],
            keywords=["sqlmap", "sql-injection", "security", "ai", "penetration-testing", "cybersecurity"],
        )
        
        # Run post-installation tasks
        run_post_install()
    else:
        # Just run setup without post-installation
        setup(
            name="sqlmap-ai",
            version="2.0.0",
            description="AI-powered SQL injection testing tool with multiple AI providers",
            long_description=read_readme(),
            long_description_content_type="text/markdown",
            author="Atilla",
            author_email="attilla@tuta.io",
            url="https://github.com/atiilla/sqlmap-ai",
            packages=find_packages(include=["sqlmap_ai*", "utils*"]),
            include_package_data=True,
            install_requires=get_requirements(),
            extras_require={
                "dev": [
                    "pytest>=7.0.0",
                    "pytest-asyncio>=0.21.0",
                    "black>=23.0.0",
                    "flake8>=6.0.0",
                    "mypy>=1.0.0",
                ],
                "local-llm": [
                    "transformers>=4.35.0",
                    "torch>=2.1.0",
                ],
                "reporting": [
                    "plotly>=5.0.0",
                    "pandas>=2.0.0",
                ],
                "all": [
                    "sqlmap-ai[dev,local-llm,reporting]",
                ],
            },
            entry_points={
                "console_scripts": [
                    "sqlmap-ai=sqlmap_ai.cli:main",
                    "sqlmapai=sqlmap_ai.cli:main",
                ],
            },
            python_requires=">=3.8",
            classifiers=[
                "Development Status :: 4 - Beta",
                "Intended Audience :: Information Technology",
                "Intended Audience :: System Administrators",
                "License :: OSI Approved :: MIT License",
                "Operating System :: OS Independent",
                "Programming Language :: Python :: 3",
                "Programming Language :: Python :: 3.8",
                "Programming Language :: Python :: 3.9",
                "Programming Language :: Python :: 3.10",
                "Programming Language :: Python :: 3.11",
                "Programming Language :: Python :: 3.12",
                "Topic :: Security",
                "Topic :: System :: Systems Administration",
                "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
                "Topic :: Software Development :: Testing",
            ],
            keywords=["sqlmap", "sql-injection", "security", "ai", "penetration-testing", "cybersecurity"],
        )
