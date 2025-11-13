#!/usr/bin/env python3
"""
SQLMap AI CLI Entry Point
Handles installation tasks and provides the main interface
"""

import sys
import os
import subprocess
import shutil
from pathlib import Path
from typing import Optional

# Add project root to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def check_sqlmap_installation() -> bool:
    """Check if SQLMap is installed and accessible"""
    try:
        # Try to run sqlmap --version
        result = subprocess.run(
            ["sqlmap", "--version"], 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
        return False

def install_sqlmap() -> bool:
    """Install SQLMap if not already installed"""
    print("🔍 Checking SQLMap installation...")
    
    if check_sqlmap_installation():
        print("✅ SQLMap is already installed")
        return True
    
    print("📦 SQLMap not found. Installing...")
    
    # Try pip installation first
    try:
        print("  Installing via pip...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "sqlmap"],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode == 0:
            print("✅ SQLMap installed via pip")
            return True
    except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
        print(f"  ❌ Pip installation failed: {e}")
    
    # Try git clone as fallback
    try:
        print("  Installing via git clone...")
        sqlmap_dir = project_root / "sqlmap"
        if sqlmap_dir.exists():
            print("  SQLMap directory already exists")
        else:
            result = subprocess.run(
                ["git", "clone", "https://github.com/sqlmapproject/sqlmap.git", str(sqlmap_dir)],
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode == 0:
                print("✅ SQLMap cloned from repository")
                return True
    except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
        print(f"  ❌ Git clone failed: {e}")
    
    print("❌ Failed to install SQLMap automatically")
    print("Please install SQLMap manually:")
    print("  pip install sqlmap")
    print("  or")
    print("  git clone https://github.com/sqlmapproject/sqlmap.git")
    return False

def create_env_template() -> bool:
    """Create .env template if it doesn't exist"""
    # Use current working directory instead of project root
    env_file = Path.cwd() / ".env"
    if env_file.exists():
        print("✅ .env file already exists")
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
        print("✅ .env template created")
        print("  Please edit .env file and add your API keys")
        return True
    except Exception as e:
        print(f"❌ Failed to create .env template: {e}")
        return False

def setup_directories() -> bool:
    """Create necessary directories"""
    print("📁 Setting up directories...")
    
    directories = [
        Path.cwd() / "reports",
        Path.cwd() / "logs",
        Path.cwd() / "config",
    ]
    
    try:
        for directory in directories:
            directory.mkdir(exist_ok=True)
        print("✅ Directories created")
        return True
    except Exception as e:
        print(f"❌ Failed to create directories: {e}")
        return False

def run_installation_checks() -> bool:
    """Run all installation checks and setup tasks"""
    print("🚀 SQLMap AI Installation Check")
    print("=" * 50)
    
    success = True
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        return False
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    
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
        print("\n🎉 Installation check completed successfully!")
        print("\nNext steps:")
        print("1. Edit .env file and add your API keys")
        print("2. Run: sqlmap-ai --config-wizard")
        print("3. Run: sqlmap-ai --help")
    else:
        print("\n⚠️  Installation check completed with issues")
        print("Please resolve the issues above before using SQLMap AI")
    
    return success

def main():
    """Main CLI entry point"""
    # Check if this is the first run (installation check)
    if len(sys.argv) == 1 or "--install-check" in sys.argv:
        if run_installation_checks():
            sys.exit(0)
        else:
            sys.exit(1)

    # Import and run the main application
    try:
        from sqlmap_ai.run import main as run_main
        run_main()
    except ImportError as e:
        print(f"❌ Failed to import main application: {e}")
        print("Please ensure all dependencies are installed:")
        print("  pip install -e .")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
