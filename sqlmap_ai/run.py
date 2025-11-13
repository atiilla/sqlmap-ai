#!/usr/bin/env python3

import sys
import os
import asyncio
import argparse
from pathlib import Path

# Import UI functions
try:
    from sqlmap_ai.ui import print_info, print_success, print_error, print_warning
    from sqlmap_ai.startup import run_first_time_setup, show_startup_animation
except ImportError:
    # Fallback UI functions if sqlmap_ai.ui is not available
    def print_info(msg): print(f"[INFO] {msg}")
    def print_success(msg): print(f"[SUCCESS] {msg}")
    def print_error(msg): print(f"[ERROR] {msg}")
    def print_warning(msg): print(f"[WARNING] {msg}")
    def run_first_time_setup(): return False
    def show_startup_animation(): pass

def show_usage():
    
    try:
        from sqlmap_ai.startup import print_sqlmapai_logo
        print_sqlmapai_logo()
    except ImportError:
        pass
    
    print("""
USAGE:
  sqlmap-ai [MODE] [OPTIONS]

MODES:
  simple     - Basic SQL injection testing (legacy mode)
  enhanced   - Advanced AI-powered testing with full features (default)

EXAMPLES:
  # Enhanced mode (default)
  sqlmap-ai -u "http://example.com/page.php?id=1"
  sqlmap-ai --enhanced -u "http://example.com/page.php?id=1"
  
  # Simple mode
  sqlmap-ai --simple -u "http://example.com/page.php?id=1"
  
  # Configuration
  sqlmap-ai --config-wizard
  sqlmap-ai --show-config

For full help: sqlmap-ai --help
For enhanced mode help: sqlmap-ai --enhanced --help
For simple mode help: sqlmap-ai --simple --help
""")

def show_simple_help():
    
    # Show SQLMap-style logo for help
    try:
        from sqlmap_ai.startup import print_sqlmapai_logo
        print_sqlmapai_logo()
    except ImportError:
        pass
    
    print("""
SQLMap AI - Simple Mode Help (Legacy Mode)

USAGE:
  sqlmap-ai --simple [OPTIONS]

DESCRIPTION:
  Simple mode provides basic SQL injection testing without AI features.
  It's faster and has minimal dependencies.

OPTIONS:
  -u, --url URL           Target URL (e.g., http://example.com/page.php?id=1)
  -r, --request-file FILE Load HTTP request from file
  --timeout SECONDS       Timeout in seconds (default: 60)
  --level LEVEL           SQLMap level (1-5, default: 1)
  --risk RISK             SQLMap risk (1-3, default: 1)
  --batch                 Never ask for user input, use default behavior
  --random-agent          Use randomly selected HTTP User-Agent header
  --save-report           Save results to file
  -h, --help              Show this help message

EXAMPLES:
  # Basic scan
  sqlmap-ai --simple -u "http://example.com/page.php?id=1"
  
  # Scan with custom options
  sqlmap-ai --simple -u "http://example.com/page.php?id=1" --level 2 --risk 2
  
  # Interactive mode (no arguments)
  sqlmap-ai --simple

FEATURES:
  * Basic SQL injection detection
  * Standard SQLMap functionality
  * Minimal dependencies
  * Fast execution
  * Simple text output
  * Basic result saving
""")

def show_enhanced_help():
    
    # Show SQLMap-style logo for help
    try:
        from sqlmap_ai.startup import print_sqlmapai_logo
        print_sqlmapai_logo()
    except ImportError:
        pass
    
    print("""
SQLMap AI - Enhanced Mode Help (AI-Powered Mode)

USAGE:
  sqlmap-ai --enhanced [OPTIONS]

DESCRIPTION:
  Enhanced mode provides AI-powered SQL injection testing with advanced features.
  It includes adaptive testing, WAF evasion, and comprehensive reporting.

OPTIONS:
  Target Specification:
    -u, --url URL           Target URL (e.g., http://example.com/page.php?id=1)
    -r, --request-file FILE Load HTTP request from file
    --crawl DEPTH           Crawl website starting from target URL (depth: 1-3)

  AI Configuration:
    --ai-provider PROVIDER  AI provider to use (groq, openai, anthropic, ollama, auto)
    --adaptive              Enable adaptive step-by-step testing
    --ai-analysis           Enable AI-powered result analysis

  Testing Options:
    --level LEVEL           SQLMap level (1-5, default: 1)
    --risk RISK             SQLMap risk (1-3, default: 1)
    --timeout SECONDS       Timeout in seconds (default: 300)
    --threads THREADS       Number of concurrent threads (default: 1)
    --batch                 Never ask for user input, use default behavior
    --random-agent          Use randomly selected HTTP User-Agent header

  WAF Evasion:
    --tamper SCRIPT         Use given script(s) for tampering injection data
    --waf-bypass            Enable automatic WAF bypass techniques

  Reporting:
    --html-report           Generate HTML report
    --json-report           Generate JSON report
    --no-report             Disable report generation
    --report-dir DIR        Directory to save reports (default: reports/)

  Configuration:
    --config-wizard         Run configuration wizard
    --show-config           Show current configuration
    --export-config FILE    Export configuration to file

  Other:
    --debug                 Enable debug mode
    --interactive           Enable interactive mode
    -h, --help              Show this help message

EXAMPLES:
  # Basic enhanced scan
  sqlmap-ai --enhanced -u "http://example.com/page.php?id=1"
  
  # Adaptive testing with AI analysis
  sqlmap-ai --enhanced -u "http://example.com/page.php?id=1" --adaptive --ai-provider groq
  
  # Using Ollama for local AI analysis
  sqlmap-ai --enhanced -u "http://example.com/page.php?id=1" --ai-provider ollama
  
  # Advanced scan with custom options
  sqlmap-ai --enhanced -u "http://example.com/page.php?id=1" --level 3 --risk 2 --threads 5
  
  # Configuration
  sqlmap-ai --enhanced --config-wizard

FEATURES:
  * AI-powered vulnerability analysis
  * Adaptive testing strategies
  * WAF evasion techniques
  * Beautiful HTML reports
  * Risk assessment and remediation guidance
  * Interactive CLI with progress tracking
  * Multiple AI providers (Groq, OpenAI, Anthropic, Ollama)
  * Advanced configuration management
  * Comprehensive logging and audit trails
""")

def create_simple_parser():
    
    parser = argparse.ArgumentParser(
        description="SQLMap AI - Simple Mode (Legacy Mode)",
        add_help=False
    )
    
    # Target options
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-r', '--request-file', help='Load HTTP request from file')
    
    # SQLMap options
    parser.add_argument('--timeout', type=int, default=60, help='Timeout in seconds')
    parser.add_argument('--level', type=int, choices=[1,2,3,4,5], default=1, help='SQLMap level')
    parser.add_argument('--risk', type=int, choices=[1,2,3], default=1, help='SQLMap risk')
    parser.add_argument('--batch', action='store_true', help='Never ask for user input')
    parser.add_argument('--random-agent', action='store_true', help='Use random User-Agent')
    
    # Output options
    parser.add_argument('--save-report', action='store_true', help='Save results to file')
    
    # Help
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')
    
    return parser

def run_simple_mode():
    
    print("[INFO] Starting SQLMap AI in SIMPLE mode (Legacy Mode)...")
    print("This mode provides basic SQL injection testing without AI features.")
    print()
    
    # Parse arguments for simple mode
    parser = create_simple_parser()
    args, unknown = parser.parse_known_args()
    
    # Show help if requested
    if args.help or len(sys.argv) == 2 and sys.argv[1] == '--simple':
        show_simple_help()
        return
    
    # If no URL provided, run interactive mode
    if not args.url and not args.request_file:
        try:
            from sqlmap_ai.main import main_simple
            main_simple()
        except ImportError:
            print("[ERROR] Simple mode not available. Falling back to enhanced mode...")
            run_enhanced_mode()
        return
    
    # Run with provided arguments
    try:
        from sqlmap_ai.runner import SQLMapRunner
        runner = SQLMapRunner()
        
        # Build SQLMap options
        options = []
        if args.batch:
            options.append("--batch")
        if args.random_agent:
            options.append("--random-agent")
        options.extend(["--level", str(args.level)])
        options.extend(["--risk", str(args.risk)])
        
        # Run scan
        result = runner.run_sqlmap(args.url, " ".join(options), timeout=args.timeout, interactive_mode=False)
        
        if result:
            print_success("Scan completed!")
            
            # Extract basic info
            from sqlmap_ai.parser import extract_sqlmap_info
            scan_info = extract_sqlmap_info(result)
            
            if scan_info.get('vulnerable_parameters'):
                print_success(f"Vulnerabilities found: {len(scan_info['vulnerable_parameters'])}")
                for param in scan_info['vulnerable_parameters']:
                    print(f"  - Parameter: {param}")
            else:
                print_info("No vulnerabilities detected")
            
            # Save report if requested
            if args.save_report:
                import time
                timestamp = int(time.time())
                filename = f"reports/simple_scan_{timestamp}.txt"
                
                import os
                os.makedirs("reports", exist_ok=True)
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"SQLMap AI Simple Scan Report\n")
                    f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Target: {args.url}\n")
                    f.write(f"Options: {' '.join(options)}\n")
                    f.write("-" * 50 + "\n")
                    f.write(result)
                
                print_success(f"Results saved to: {filename}")
        else:
            print_error("Scan failed or no results obtained")
            
    except Exception as e:
        print_error(f"Error during scan: {e}")
        print_info("Try enhanced mode for more features and better error handling")

def run_enhanced_mode():
    
    print("Starting SQLMap AI in ENHANCED mode (AI-Powered Mode)...")
    print("This mode includes AI-powered analysis, adaptive testing, and advanced features.")
    print()
    
    # Import and run enhanced version
    try:
        from sqlmap_ai.main import main
        # Pass the modified sys.argv to main
        main()
    except ImportError as e:
        print(f"[ERROR] Enhanced mode failed to load: {e}")
        print("Falling back to simple mode...")
        run_simple_mode()

def main():
    
    # Check if this is a first run and show startup animation
    first_run = run_first_time_setup()
    
    # Check for mode-specific help first
    if "--simple" in sys.argv:
        if "--help" in sys.argv or "-h" in sys.argv or len(sys.argv) == 2:
            show_simple_help()
            return
    
    if "--enhanced" in sys.argv:
        if "--help" in sys.argv or "-h" in sys.argv:
            show_enhanced_help()
            return
    
    # Check for general help
    if len(sys.argv) == 1 or "--help" in sys.argv or "-h" in sys.argv:
        # Show startup animation if no arguments provided
        if len(sys.argv) == 1 and not first_run:
            show_startup_animation()
        show_usage()
        return
    
    # Check for mode flags
    args = sys.argv[1:]
    
    # Remove mode flags from args for passing to main functions
    if "--simple" in args:
        args.remove("--simple")
        # Update sys.argv for the main function
        sys.argv = [sys.argv[0]] + args
        run_simple_mode()
    elif "--enhanced" in args:
        args.remove("--enhanced")
        # Update sys.argv for the main function
        sys.argv = [sys.argv[0]] + args
        run_enhanced_mode()
    else:
        # Default to enhanced mode
        run_enhanced_mode()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        print("Try running with --help for usage information")
        sys.exit(1) 