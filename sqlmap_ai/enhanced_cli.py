import argparse
import sys
import os
from typing import Dict, List, Optional, Any
from pathlib import Path
import json
from dataclasses import asdict

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Prompt, Confirm
    from rich.tree import Tree
    from rich.syntax import Syntax
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from sqlmap_ai.config_manager import config_manager, get_config
from sqlmap_ai.security_manager import security_manager
from utils.ai_providers import get_available_ai_providers


class EnhancedCLI:
    
    
    def __init__(self):
        self.console = Console() if HAS_RICH else None
        self.config = get_config()
    
    def print_banner(self):
        
        # Use SQLMap-style logo for consistency
        try:
            from sqlmap_ai.startup import print_sqlmapai_logo
            print_sqlmapai_logo()
        except ImportError:
            # Fallback banner
            if HAS_RICH and self.console:
                banner_text = """
╔═══════════════════════════════════════════════════════════════╗
║                       SQLMap AI v2.0                          ║
║        Advanced AI-Powered SQL Injection Testing Tool         ║
║             Powered by Artificial Intelligence                ║
╚═══════════════════════════════════════════════════════════════╝
                """
                self.console.print(Panel(banner_text, style="bold blue"))
            else:
                print("""
────────────────────────────────────────────────────────────────
                        SQLMap AI v2.0
          Advanced AI-Powered SQL Injection Testing Tool
                 Powered by Artificial Intelligence
────────────────────────────────────────────────────────────────
            """)
    
    def create_parser(self) -> argparse.ArgumentParser:
        
        parser = argparse.ArgumentParser(
            description="SQLMap AI - Advanced SQL Injection Testing Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s -u "http://example.com/page.php?id=1" --adaptive
  %(prog)s -u "http://example.com/login.php" --ai-provider groq --risk 2
  %(prog)s --config-wizard
  %(prog)s --scan-history
  %(prog)s --export-config config_backup.yaml

For more information, visit: https://github.com/atiilla/sqlmap-ai
            """
        )
        
        # Target specification
        target_group = parser.add_argument_group('Target Specification')
        target_group.add_argument(
            '-u', '--url',
            help='Target URL (e.g., "http://example.com/page.php?id=1")'
        )
        target_group.add_argument(
            '-r', '--request-file',
            help='Load HTTP request from file'
        )
        target_group.add_argument(
            '--crawl',
            type=int,
            metavar='DEPTH',
            help='Crawl website starting from target URL (depth: 1-3)'
        )
        
        # AI Configuration
        ai_group = parser.add_argument_group('AI Configuration')
        ai_group.add_argument(
            '--ai-provider',
            choices=['groq', 'openai', 'anthropic', 'local', 'ollama', 'auto'],
            default='auto',
            help='AI provider to use (default: auto)'
        )
        ai_group.add_argument(
            '--ai-model',
            help='Specific AI model to use'
        )
        ai_group.add_argument(
            '--ollama-model',
            help='Specific Ollama model to use (overrides OLLAMA_MODEL env var)'
        )
        ai_group.add_argument(
            '--advanced',
            action='store_true',
            help='Use advanced AI prompts (default: simple for Ollama, advanced for other providers)'
        )
        ai_group.add_argument(
            '--simple',
            action='store_true',
            help='Use simple AI prompts (default: simple for Ollama, advanced for other providers)'
        )
        ai_group.add_argument(
            '--disable-ai',
            action='store_true',
            help='Disable AI assistance and run in basic mode'
        )
        
        # Scanning Options
        scan_group = parser.add_argument_group('Scanning Options')
        scan_group.add_argument(
            '--adaptive',
            action='store_true',
            help='Use adaptive step-by-step testing'
        )
        scan_group.add_argument(
            '--aggressive',
            action='store_true',
            help='Use aggressive testing (higher risk/level)'
        )
        scan_group.add_argument(
            '--stealth',
            action='store_true',
            help='Use stealth mode (slower but more evasive)'
        )
        scan_group.add_argument(
            '--timeout',
            type=int,
            default=120,
            help='Scan timeout in seconds (default: 120)'
        )
        scan_group.add_argument(
            '--threads',
            type=int,
            help='Number of threads (1-20)'
        )
        scan_group.add_argument(
            '--risk',
            type=int,
            choices=[1, 2, 3],
            help='Risk level (1-3, default from config)'
        )
        scan_group.add_argument(
            '--level',
            type=int,
            choices=[1, 2, 3, 4, 5],
            help='Test level (1-5, default from config)'
        )
        scan_group.add_argument(
            '-p', '--param',
            dest='test_parameter',
            help='Specific parameter(s) to test (comma-separated)'
        )

        # WAF Evasion
        evasion_group = parser.add_argument_group('WAF Evasion')
        evasion_group.add_argument(
            '--tamper',
            help='Comma-separated list of tamper scripts'
        )
        evasion_group.add_argument(
            '--auto-tamper',
            action='store_true',
            help='Automatically select tamper scripts based on WAF detection'
        )
        evasion_group.add_argument(
            '--random-agent',
            action='store_true',
            help='Use random User-Agent strings'
        )
        
        # Output and Reporting
        output_group = parser.add_argument_group('Output and Reporting')
        output_group.add_argument(
            '--output-format',
            choices=['html', 'pdf', 'json', 'all'],
            help='Report output format'
        )
        output_group.add_argument(
            '--output-dir',
            help='Output directory for reports'
        )
        output_group.add_argument(
            '--no-report',
            action='store_true',
            help='Skip report generation'
        )
        output_group.add_argument(
            '--interactive',
            action='store_true',
            help='Run in interactive mode'
        )
        
        # Configuration Management
        config_group = parser.add_argument_group('Configuration')
        config_group.add_argument(
            '--config',
            help='Load configuration from file'
        )
        config_group.add_argument(
            '--config-wizard',
            action='store_true',
            help='Run configuration wizard'
        )
        config_group.add_argument(
            '--show-config',
            action='store_true',
            help='Show current configuration'
        )
        config_group.add_argument(
            '--export-config',
            help='Export configuration to file'
        )
        config_group.add_argument(
            '--validate-config',
            action='store_true',
            help='Validate current configuration'
        )
        
        # Utility Options
        utility_group = parser.add_argument_group('Utility')
        utility_group.add_argument(
            '--scan-history',
            action='store_true',
            help='Show recent scan history'
        )
        utility_group.add_argument(
            '--list-ollama-models',
            action='store_true',
            help='List available Ollama models'
        )
        utility_group.add_argument(
            '--check-providers',
            action='store_true',
            help='Check AI provider availability'
        )
        utility_group.add_argument(
            '--security-status',
            action='store_true',
            help='Show security status'
        )
        utility_group.add_argument(
            '--version',
            action='version',
            version=f'SQLMap AI v{self.config.version}'
        )
        
        # Debug Options
        debug_group = parser.add_argument_group('Debug')
        debug_group.add_argument(
            '--debug',
            action='store_true',
            help='Enable debug mode'
        )
        debug_group.add_argument(
            '--verbose',
            '-v',
            action='store_true',
            help='Verbose output'
        )
        debug_group.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be executed without running'
        )
        
        return parser
    
    def run_config_wizard(self):
        
        if not HAS_RICH:
            print("Configuration wizard requires 'rich' library. Please install it.")
            return

        self.console.print(Panel("Configuration Wizard", style="bold green"))

        # AI Provider Selection
        self.console.print("\n[bold cyan]Step 1: Select AI Provider[/bold cyan]")
        self.console.print("Choose which AI provider you want to use:\n")

        provider_options = [
            ("1", "Groq", "Fast and free API (recommended for beginners)"),
            ("2", "OpenAI", "GPT models (requires paid API key)"),
            ("3", "Anthropic", "Claude models (requires paid API key)"),
            ("4", "Ollama", "Local AI provider (free, requires Ollama installation)"),
        ]

        for num, name, desc in provider_options:
            self.console.print(f"  [bold]{num}.[/bold] {name} - {desc}")

        while True:
            choice = Prompt.ask("\nSelect provider (1-4)", default="1")
            if choice in ["1", "2", "3", "4"]:
                break
            self.console.print("[red]Invalid choice. Please enter 1, 2, 3, or 4.[/red]")

        provider_map = {
            "1": ("groq", "Groq", "GROQ_API_KEY"),
            "2": ("openai", "OpenAI", "OPENAI_API_KEY"),
            "3": ("anthropic", "Anthropic", "ANTHROPIC_API_KEY"),
            "4": ("ollama", "Ollama", None)
        }

        selected_provider, provider_name, env_var = provider_map[choice]

        # Configure selected provider
        self.console.print(f"\n[bold]Configuring {provider_name}[/bold]")

        if selected_provider == "ollama":
            # Handle Ollama configuration
            self._configure_ollama()
            # Update config to set Ollama as primary provider
            config_manager.update_ai_provider("ollama", enabled=True, priority=1)
            # Disable other providers or set lower priority
            for other_provider in ["groq", "openai", "anthropic"]:
                config_manager.update_ai_provider(other_provider, enabled=False)
        else:
            # Handle API key-based providers
            self.console.print(f"\n[bold cyan]Step 2: API Key Configuration[/bold cyan]")

            # Check if API key already exists
            current_key = os.getenv(env_var)
            if current_key:
                self.console.print(f"[green]✓ API key for {provider_name} is already set[/green]")
                if not Confirm.ask("Would you like to update it?", default=False):
                    # Key exists and user doesn't want to change it, just enable the provider
                    config_manager.update_ai_provider(selected_provider, enabled=True, priority=1)
                    # Disable other providers
                    for other_provider in ["groq", "openai", "anthropic", "ollama"]:
                        if other_provider != selected_provider:
                            config_manager.update_ai_provider(other_provider, enabled=False)
                    self.console.print(f"[green]✓ {provider_name} is now configured as your primary AI provider[/green]")
                    self._finalize_config()
                    return

            # Prompt for API key
            self.console.print(f"\nTo use {provider_name}, you need an API key.")
            self.console.print(f"You can get one from:")

            api_urls = {
                "groq": "https://console.groq.com/keys",
                "openai": "https://platform.openai.com/api-keys",
                "anthropic": "https://console.anthropic.com/settings/keys"
            }

            if selected_provider in api_urls:
                self.console.print(f"  → {api_urls[selected_provider]}")

            self.console.print()
            api_key = Prompt.ask(f"Enter your {provider_name} API key", password=True)

            if api_key and api_key.strip():
                # Save to config.yaml instead of .env
                self._save_api_key_to_config(env_var, api_key.strip())
                self.console.print(f"[green]✓ {provider_name} API key saved to config.yaml[/green]")

                # Update provider configuration
                config_manager.update_ai_provider(selected_provider, enabled=True, priority=1)

                # Disable other providers
                for other_provider in ["groq", "openai", "anthropic", "ollama"]:
                    if other_provider != selected_provider:
                        config_manager.update_ai_provider(other_provider, enabled=False)

                self.console.print(f"[green]✓ {provider_name} is now configured as your primary AI provider[/green]")
            else:
                self.console.print("[yellow]⚠ No API key provided. Provider will not be enabled.[/yellow]")
                return
        
        # Finalize configuration
        self._finalize_config()

    def _configure_ollama(self):
        
        self.console.print("\n[bold cyan]Step 2: Ollama Model Selection[/bold cyan]")

        # Enable Ollama in environment
        self._update_env_file("ENABLE_OLLAMA", "true")

        # Check if Ollama is running and get available models
        available_models = self._get_ollama_models()

        if available_models:
            self.console.print(f"\n[green]✓ Found {len(available_models)} Ollama model(s):[/green]")
            for i, model in enumerate(available_models, 1):
                self.console.print(f"  {i}. {model}")

            self.console.print(f"  {len(available_models) + 1}. Enter custom model name")

            while True:
                try:
                    choice = Prompt.ask(
                        f"Select model (1-{len(available_models) + 1})",
                        default="1"
                    )

                    choice_num = int(choice)
                    if 1 <= choice_num <= len(available_models):
                        selected_model = available_models[choice_num - 1]
                        self._update_env_file("OLLAMA_MODEL", selected_model)
                        self.console.print(f"[green]✓ Model set to: {selected_model}[/green]")
                        break
                    elif choice_num == len(available_models) + 1:
                        custom_model = Prompt.ask("Enter model name (e.g., llama3.2, codellama, mistral)")
                        if custom_model:
                            self._update_env_file("OLLAMA_MODEL", custom_model)
                            self.console.print(f"[green]✓ Model set to: {custom_model}[/green]")
                            break
                    else:
                        self.console.print(f"[red]Invalid selection. Please enter 1-{len(available_models) + 1}.[/red]")
                except ValueError:
                    self.console.print("[red]Invalid input. Please enter a number.[/red]")
        else:
            self.console.print("[yellow]⚠ No models found. Ollama might not be running or no models are installed.[/yellow]")
            self.console.print("\n[bold]To get started:[/bold]")
            self.console.print("  1. Start Ollama: ollama serve")
            self.console.print("  2. Download a model: ollama pull llama3.2")
            self.console.print()

            custom_model = Prompt.ask("Enter model name to use", default="llama3.2")
            self._update_env_file("OLLAMA_MODEL", custom_model)
            self.console.print(f"[green]✓ Model set to: {custom_model}[/green]")

    def _save_api_key_to_config(self, env_var: str, api_key: str):
        
        # Also update environment for current session
        os.environ[env_var] = api_key
        # Update .env file for persistence
        self._update_env_file(env_var, api_key)

    def _finalize_config(self):
        
        self.console.print("\n[bold cyan]Step 3: Additional Settings[/bold cyan]")

        # Security Configuration
        self.console.print("\n[bold]Security Configuration[/bold]")

        safe_mode = Confirm.ask("Enable safe mode (recommended)?", default=True)
        config_manager.config.security.safe_mode = safe_mode

        rate_limit = Prompt.ask(
            "Max requests per minute",
            default=str(config_manager.config.security.max_requests_per_minute)
        )
        config_manager.config.security.max_requests_per_minute = int(rate_limit)

        # SQLMap Configuration
        self.console.print("\n[bold]SQLMap Configuration[/bold]")

        timeout = Prompt.ask(
            "Default scan timeout (seconds)",
            default=str(config_manager.config.sqlmap.default_timeout)
        )
        config_manager.config.sqlmap.default_timeout = int(timeout)

        # Save configuration
        if config_manager.save_config():
            self.console.print("\n[green]✓ Configuration saved successfully![/green]")
            self.console.print("\n[bold]Next steps:[/bold]")
            self.console.print("  • Run a scan: sqlmap-ai -u <target_url>")
            self.console.print("  • View config: sqlmap-ai --show-config")
            self.console.print("  • Get help: sqlmap-ai --help")
        else:
            self.console.print("[red]✗ Failed to save configuration[/red]")
    
    def _get_ollama_models(self) -> list:
        
        try:
            import requests
            import json
            
            # Try to connect to Ollama API
            base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
            response = requests.get(f"{base_url}/api/tags", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                models = []
                for model in data.get("models", []):
                    model_name = model.get("name", "")
                    # Remove version tags (e.g., "llama3.2:latest" -> "llama3.2")
                    if ":" in model_name:
                        model_name = model_name.split(":")[0]
                    models.append(model_name)
                return list(set(models))  # Remove duplicates
            else:
                return []
        except Exception as e:
            # Silently fail - Ollama might not be running
            return []
    
    def _update_env_file(self, key: str, value: str):
        
        env_file = Path(".env")
        lines = []
        
        if env_file.exists():
            lines = env_file.read_text().splitlines()
        
        # Remove existing key
        lines = [line for line in lines if not line.startswith(f"{key}=")]
        
        # Add new key
        lines.append(f"{key}={value}")
        
        # Write back
        env_file.write_text("\n".join(lines))
    
    def show_config(self):
        
        if HAS_RICH and self.console:
            self._show_config_rich()
        else:
            self._show_config_simple()
    
    def _show_config_rich(self):
        
        config_summary = config_manager.get_config_summary()
        
        # Create configuration table
        table = Table(title="SQLMap AI Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in config_summary.items():
            if isinstance(value, list):
                value = ", ".join(value) if value else "None"
            table.add_row(key.replace("_", " ").title(), str(value))
        
        self.console.print(table)
        
        # AI Providers status
        self.console.print("\n[bold]AI Providers[/bold]")
        providers_table = Table()
        providers_table.add_column("Provider", style="cyan")
        providers_table.add_column("Status", style="green")
        providers_table.add_column("Model", style="yellow")
        providers_table.add_column("Priority", style="magenta")
        
        for provider in config_manager.get_enabled_ai_providers():
            status = "[X] Enabled" if provider.enabled else "X Disabled"
            providers_table.add_row(
                provider.name.title(),
                status,
                provider.model,
                str(provider.priority)
            )
        
        self.console.print(providers_table)
    
    def _show_config_simple(self):
        
        config_summary = config_manager.get_config_summary()
        
        print("\nSQLMap AI Configuration:")
        print("=" * 50)
        
        for key, value in config_summary.items():
            if isinstance(value, list):
                value = ", ".join(value) if value else "None"
            print(f"{key.replace('_', ' ').title()}: {value}")
        
        print("\nAI Providers:")
        print("-" * 30)
        
        for provider in config_manager.get_enabled_ai_providers():
            status = "Enabled" if provider.enabled else "Disabled"
            print(f"{provider.name.title()}: {status} ({provider.model})")
    
    def validate_config(self):
        
        issues = config_manager.validate_config()
        
        if HAS_RICH and self.console:
            if issues:
                self.console.print(Panel(
                    "\n".join([f"• {issue}" for issue in issues]),
                    title="Configuration Issues",
                    border_style="red"
                ))
            else:
                self.console.print(Panel(
                    "Configuration is valid ✅",
                    border_style="green"
                ))
        else:
            if issues:
                print("\nConfiguration Issues:")
                for issue in issues:
                    print(f"  - {issue}")
            else:
                print("[X] Configuration is valid")
    
    def check_providers(self):
        
        if HAS_RICH and self.console:
            self.console.print(Panel("AI Provider Status Check", style="bold blue"))
            
            providers_table = Table()
            providers_table.add_column("Provider", style="cyan")
            providers_table.add_column("API Key", style="yellow")
            providers_table.add_column("Status", style="green")
            
            providers = {
                'Groq': 'GROQ_API_KEY',
                'OpenAI': 'OPENAI_API_KEY',
                'Anthropic': 'ANTHROPIC_API_KEY',
                'Ollama': 'ENABLE_OLLAMA'
            }
            
            for provider, env_var in providers.items():
                if provider == 'Ollama':
                    has_key = "[X] Enabled" if os.getenv(env_var, "false").lower() == "true" else "X Disabled"
                    status = "Available" if os.getenv(env_var, "false").lower() == "true" else "Unavailable"
                else:
                    has_key = "[X] Set" if os.getenv(env_var) else "X Missing"
                    status = "Available" if os.getenv(env_var) else "Unavailable"
                
                providers_table.add_row(provider, has_key, status)
            
            self.console.print(providers_table)
        else:
            print("\nAI Provider Status:")
            providers = {
                'Groq': 'GROQ_API_KEY',
                'OpenAI': 'OPENAI_API_KEY',
                'Anthropic': 'ANTHROPIC_API_KEY',
                'Ollama': 'ENABLE_OLLAMA'
            }
            
            for provider, env_var in providers.items():
                if provider == 'Ollama':
                    status = "Available" if os.getenv(env_var, "false").lower() == "true" else "Disabled"
                else:
                    status = "Available" if os.getenv(env_var) else "Missing API Key"
                print(f"  {provider}: {status}")
    
    def show_security_status(self):
        
        status = security_manager.get_security_summary()
        
        if HAS_RICH and self.console:
            table = Table(title="Security Status")
            table.add_column("Setting", style="cyan")
            table.add_column("Value", style="green")
            
            for key, value in status.items():
                table.add_row(key.replace("_", " ").title(), str(value))
            
            self.console.print(table)
        else:
            print("\nSecurity Status:")
            for key, value in status.items():
                print(f"  {key.replace('_', ' ').title()}: {value}")
    
    def list_ollama_models(self):
        
        if HAS_RICH and self.console:
            self.console.print(Panel("Ollama Models", style="bold blue"))
        else:
            print("\nOllama Models:")
        
        # Check if Ollama is enabled
        ollama_enabled = os.getenv("ENABLE_OLLAMA", "false").lower() == "true"
        current_model = os.getenv("OLLAMA_MODEL", "llama3.2")
        
        if not ollama_enabled:
            if HAS_RICH and self.console:
                self.console.print("[yellow]Ollama is not enabled. Enable it in the configuration wizard.[/yellow]")
            else:
                print("Ollama is not enabled. Enable it in the configuration wizard.")
            return
        
        # Get available models
        available_models = self._get_ollama_models()
        
        if available_models:
            if HAS_RICH and self.console:
                self.console.print(f"[green]Found {len(available_models)} model(s):[/green]")
                
                # Create table
                table = Table()
                table.add_column("Model", style="cyan")
                table.add_column("Status", style="green")
                
                for model in available_models:
                    status = "[X] Current" if model == current_model else "Available"
                    table.add_row(model, status)
                
                self.console.print(table)
                
                # Show current model
                self.console.print(f"\n[bold]Current model:[/bold] {current_model}")
                
                # Show usage instructions
                self.console.print("\n[bold]Usage:[/bold]")
                self.console.print("  • Use --config-wizard to change the model")
                self.console.print("  • Download new models: ollama pull <model_name>")
                self.console.print("  • Start Ollama service: ollama serve")
            else:
                print(f"Found {len(available_models)} model(s):")
                for model in available_models:
                    status = " (Current)" if model == current_model else ""
                    print(f"  • {model}{status}")
                
                print(f"\nCurrent model: {current_model}")
                print("\nUsage:")
                print("  • Use --config-wizard to change the model")
                print("  • Download new models: ollama pull <model_name>")
                print("  • Start Ollama service: ollama serve")
        else:
            if HAS_RICH and self.console:
                self.console.print("[yellow]No models found. Ollama might not be running or no models are installed.[/yellow]")
                self.console.print("\n[bold]To get started:[/bold]")
                self.console.print("  1. Start Ollama: ollama serve")
                self.console.print("  2. Download a model: ollama pull llama3.2")
                self.console.print("  3. Run configuration wizard: sqlmap-ai --config-wizard")
            else:
                print("No models found. Ollama might not be running or no models are installed.")
                print("\nTo get started:")
                print("  1. Start Ollama: ollama serve")
                print("  2. Download a model: ollama pull llama3.2")
                print("  3. Run configuration wizard: sqlmap-ai --config-wizard")
    
    def show_scan_history(self):
        
        # This would integrate with a scan history tracking system
        if HAS_RICH and self.console:
            self.console.print(Panel("Recent Scan History", style="bold blue"))
            self.console.print("No scan history available yet.")
        else:
            print("\nRecent Scan History:")
            print("No scan history available yet.")
    
    def export_config(self, output_path: str):
        
        success = config_manager.export_config(output_path, include_sensitive=False)
        
        if success:
            if HAS_RICH and self.console:
                self.console.print(f"[X] Configuration exported to {output_path}")
            else:
                print(f"[X] Configuration exported to {output_path}")
        else:
            if HAS_RICH and self.console:
                self.console.print(f"X Failed to export configuration")
            else:
                print(f"X Failed to export configuration")


def create_cli() -> argparse.ArgumentParser:
    
    cli = EnhancedCLI()
    return cli.create_parser()


def handle_cli_commands(args: argparse.Namespace) -> bool:
    
    cli = EnhancedCLI()
    
    # Show banner unless disabled
    if get_config().ui.show_banner and not any([
        args.config_wizard, args.show_config, args.validate_config,
        args.check_providers, args.security_status, args.scan_history
    ]):
        cli.print_banner()
    
    # Configuration wizard
    if args.config_wizard:
        cli.run_config_wizard()
        return True
    
    # Show configuration
    if args.show_config:
        cli.show_config()
        return True
    
    # Validate configuration
    if args.validate_config:
        cli.validate_config()
        return True
    
    # Export configuration
    if args.export_config:
        cli.export_config(args.export_config)
        return True
    
    # Check providers
    if args.check_providers:
        cli.check_providers()
        return True
    
    # List Ollama models
    if args.list_ollama_models:
        cli.list_ollama_models()
        return True
    
    # Security status
    if args.security_status:
        cli.show_security_status()
        return True
    
    # Scan history
    if args.scan_history:
        cli.show_scan_history()
        return True
    
    return False


if __name__ == "__main__":
    # Test CLI
    cli = EnhancedCLI()
    parser = cli.create_parser()
    args = parser.parse_args()
    
    if handle_cli_commands(args):
        sys.exit(0)
    else:
        print("No command specified. Use --help for usage information.")
        sys.exit(1)
