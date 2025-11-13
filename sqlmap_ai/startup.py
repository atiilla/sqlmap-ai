import time
import sys
import os
from colorama import init, Fore, Style
from sqlmap_ai.ui import print_info, print_success, print_error, print_warning

# Initialize colorama
init()

def print_sqlmapai_logo():
    logo_lines = [
        "",
        "▄▀▀▀▄  v2.0.7",
        "█░░░█  https://github.com/atiilla/sqlmap-ai",
        "█░░░█  AI-Powered SQL Injection Testing",
        "▀█░█▀ ",
        "  ▀  ",
        ""
    ]
    
    for line in logo_lines:
        if line.strip():
            if "v2.0.7" in line or "___" in line or "[" in line:
                print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
            elif "https://" in line:
                print(f"{Fore.YELLOW}{line}{Style.RESET_ALL}")
            elif "SQLMap AI" in line:
                print(f"{Fore.GREEN}{line}{Style.RESET_ALL}")
            else:
                print(line)
        else:
            print(line)

def print_animated_logo():
    logo_lines = [
        "",
        "  ███████╗ ██████╗ ██╗     ███╗   ███╗ █████╗ ██████╗      █████╗ ██╗",
        "  ██╔════╝██╔═══██╗██║     ████╗ ████║██╔══██╗██╔══██╗    ██╔══██╗██║",
        "  ███████╗██║   ██║██║     ██╔████╔██║███████║██████╔╝    ███████║██║",
        "  ╚════██║██║▄▄ ██║██║     ██║╚██╔╝██║██╔══██║██╔═══╝     ██╔══██║██║",
        "  ███████║╚██████╔╝███████╗██║ ╚═╝ ██║██║  ██║██║         ██║  ██║██║",
        "  ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝         ╚═╝  ╚═╝╚═╝",
        "",
        "            Next Generation AI-Powered SQL Injection Testing",
        "                    Developed by @atiilla | Version 2.0",
        ""
    ]
    
    # Clear screen
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Print logo with animation
    for line in logo_lines:
        if line.strip():
            if "███" in line or "╗" in line or "╚" in line:
                print(f"{Fore.RED}{line}{Style.RESET_ALL}")
            elif "Next Generation" in line:
                print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
            elif "Developed by" in line:
                print(f"{Fore.YELLOW}{line}{Style.RESET_ALL}")
            else:
                print(line)
        else:
            print(line)
        time.sleep(0.1)

def animate_text(text, color=Fore.GREEN, delay=0.03):
    """Animate text character by character"""
    for char in text:
        sys.stdout.write(f"{color}{char}{Style.RESET_ALL}")
        sys.stdout.flush()
        time.sleep(delay)
    print()

def show_loading_bar(text, duration=2.0, width=40):
    """Show animated loading bar"""
    print(f"\n{text}")
    
    for i in range(width + 1):
        percent = int((i / width) * 100)
        filled = '=' * i
        empty = '-' * (width - i)
        bar = f"[{filled}{empty}] {percent}%"
        
        sys.stdout.write(f"\r{Fore.CYAN}{bar}{Style.RESET_ALL}")
        sys.stdout.flush()
        time.sleep(duration / width)
    
    print(f" {Fore.GREEN}Complete!{Style.RESET_ALL}")

def check_installation():
    """Check installation with animated feedback"""
    print(f"\n{Fore.YELLOW}SQLMap AI Installation Check{Style.RESET_ALL}")
    print("=" * 50)
    
    # Check Python version
    print_info("Checking Python version...", end="", flush=True)
    time.sleep(0.5)
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    print(f" {Fore.GREEN}Python {python_version}{Style.RESET_ALL}")
    
    # Check SQLMap installation
    print_info("Checking SQLMap installation...", end="", flush=True)
    time.sleep(0.8)
    
    # Try to find sqlmap
    sqlmap_found = False
    try:
        import subprocess
        result = subprocess.run(['sqlmap', '--version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            sqlmap_found = True
    except:
        pass
    
    if sqlmap_found:
        print(f" {Fore.GREEN}SQLMap is installed{Style.RESET_ALL}")
    else:
        print(f" {Fore.YELLOW}SQLMap not found in PATH{Style.RESET_ALL}")
    
    # Check .env file
    print_info("Checking configuration...", end="", flush=True)
    time.sleep(0.5)
    
    env_exists = os.path.exists('.env')
    if env_exists:
        print(f" {Fore.GREEN}.env file found{Style.RESET_ALL}")
    else:
        print(f" {Fore.YELLOW}Creating .env template{Style.RESET_ALL}")
        create_env_template()
    
    # Check directories
    print_info("Setting up directories...", end="", flush=True)
    time.sleep(0.3)
    
    directories = ['reports', 'logs', 'temp']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    print(f" {Fore.GREEN}Directories created{Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}Installation check completed successfully!{Style.RESET_ALL}")
    
    if not env_exists:
        print(f"{Fore.YELLOW}Please edit .env file and add your API keys{Style.RESET_ALL}")

def create_env_template():
    """Create .env template file"""
    template_content = """# SQLMap AI Configuration
# Copy this file to .env and fill in your API keys

# AI Provider API Keys (at least one required)
GROQ_API_KEY=your_groq_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here

# Ollama Configuration (for local AI)
ENABLE_OLLAMA=false
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama2

# SQLMap Configuration
SQLMAP_PATH=sqlmap
DEFAULT_TIMEOUT=300
DEFAULT_THREADS=1

# Security Settings
MAX_SCAN_DURATION=3600
ALLOWED_HOSTS=*
RATE_LIMIT=10

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/sqlmap_ai.log
"""
    
    try:
        with open('.env.template', 'w') as f:
            f.write(template_content)
    except Exception as e:
        print_warning(f"Could not create .env template: {e}")

def show_startup_animation():
    """Main startup animation sequence"""
    # Show logo
    print_animated_logo()
    
    # Wait a moment
    time.sleep(1)
    
    # Show loading animation
    show_loading_bar("Initializing SQLMap AI...", duration=1.5)
    
    # Check installation
    check_installation()
    
    # Final message
    time.sleep(0.5)
    print(f"\n{Fore.CYAN}Welcome to SQLMap AI!{Style.RESET_ALL}")
    animate_text("Ready to start your security testing journey...", Fore.GREEN, 0.02)
    
    time.sleep(1)

def show_quick_start_guide():
    """Show quick start guide for first-time users"""
    print(f"\n{Fore.CYAN}Quick Start Guide:{Style.RESET_ALL}")
    print("-" * 20)
    print(f"{Fore.YELLOW}1.{Style.RESET_ALL} Basic scan: {Fore.GREEN}sqlmap-ai -u 'http://target.com/page.php?id=1'{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}2.{Style.RESET_ALL} Enhanced mode: {Fore.GREEN}sqlmap-ai --enhanced -u 'http://target.com/page.php?id=1'{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}3.{Style.RESET_ALL} Configuration: {Fore.GREEN}sqlmap-ai --config-wizard{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}4.{Style.RESET_ALL} Help: {Fore.GREEN}sqlmap-ai --help{Style.RESET_ALL}")
    print()

def is_first_run():
    """Check if this is the first run"""
    first_run_marker = '.sqlmap_ai_first_run'
    if not os.path.exists(first_run_marker):
        # Create marker file
        try:
            with open(first_run_marker, 'w') as f:
                f.write(f"First run completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            return True
        except:
            pass
    return False

def run_first_time_setup():
    """Run first-time setup with animations"""
    if is_first_run():
        show_startup_animation()
        show_quick_start_guide()
        return True
    return False
