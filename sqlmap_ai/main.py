import time
import argparse
import asyncio
from sqlmap_ai.ui import (
    print_banner, 
    print_info, 
    print_success, 
    print_error, 
    print_warning,
    get_target_url,
    get_timeout,
    get_interactive_mode,
    get_user_choice,
    confirm_save_report
)
from sqlmap_ai.enhanced_cli import create_cli, handle_cli_commands, EnhancedCLI
from sqlmap_ai.config_manager import config_manager, get_config, calculate_adaptive_timeout
from sqlmap_ai.security_manager import security_manager, SecurityError
from sqlmap_ai.runner import SQLMapRunner
from sqlmap_ai.parser import display_report, save_report_to_file, extract_sqlmap_info, create_json_report
from sqlmap_ai.ai_analyzer import ai_suggest_next_steps
from sqlmap_ai.timeout_handler import handle_timeout_response
from sqlmap_ai.adaptive_testing import run_adaptive_test_sequence
from sqlmap_ai.advanced_reporting import report_generator
from sqlmap_ai.evasion_engine import evasion_engine
from utils.ai_providers import ai_manager, get_available_ai_providers, AIProvider
from typing import Optional
def main():
    """Enhanced main function with improved CLI and security"""
    # Create enhanced CLI parser
    parser = create_cli()
    args = parser.parse_args()
    
    # Handle utility commands that don't require scanning
    if handle_cli_commands(args):
        return
    
    # Validate configuration
    config_issues = config_manager.validate_config()
    if config_issues:
        print_error("Configuration issues found:")
        for issue in config_issues:
            print_error(f"  - {issue}")
        if not args.debug:
            print_info("Use --config-wizard to fix configuration issues")
            return
    
    # Check if we have a target
    target_url = get_target_url_from_args(args)
    if not target_url:
        if args.interactive:
            target_url = get_target_url()
        else:
            print_error("No target specified. Use -u/--url or -r/--request-file")
            print_info("Use --help for usage information")
            return
    
    try:
        # Security validation
        options = build_sqlmap_options(args)
        valid, error = security_manager.validate_scan_request(target_url, options)
        if not valid:
            print_error(f"Security validation failed: {error}")
            return
        
        # Initialize components
        config = get_config()
        runner = SQLMapRunner()
        
        # Set timeout
        user_timeout = args.timeout or config.sqlmap.default_timeout
        interactive_mode = args.interactive or config.ui.interactive_mode
        
        print_info(f"Using timeout of {user_timeout} seconds")
        print_info(f"Available AI providers: {', '.join(get_available_ai_providers())}")
        
        # Register scan start
        scan_id = security_manager.register_scan_start(target_url, options)
        
        # Run scan based on mode
        if args.adaptive:
            result = run_enhanced_adaptive_mode(runner, target_url, user_timeout, interactive_mode, args)
        else:
            result = run_enhanced_standard_mode(runner, target_url, user_timeout, interactive_mode, args)
        
        # Generate reports if requested
        if result and not args.no_report:
            generate_enhanced_reports(result, args)
        
        # Register scan completion
        vuln_count = len(result.get('vulnerabilities', [])) if result else 0
        security_manager.register_scan_complete(scan_id, target_url, vuln_count)
        
    except SecurityError as e:
        print_error(f"Security error: {e}")
    except KeyboardInterrupt:
        print_warning("Scan interrupted by user")
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()


def build_sqlmap_options(args) -> list:
    """Build SQLMap options from CLI arguments"""
    options = ["--batch"]  # Always use batch mode for automation
    
    config = get_config()
    
    # Add request file if provided
    if args.request_file:
        options.extend(["-r", args.request_file])
    
    # Add risk and level
    risk = args.risk or config.sqlmap.default_risk
    level = args.level or config.sqlmap.default_level
    
    options.extend([f"--risk={risk}", f"--level={level}"])
    
    # Add threads
    threads = args.threads or config.sqlmap.default_threads
    options.append(f"--threads={threads}")

    # Add specific parameter to test
    if hasattr(args, 'test_parameter') and args.test_parameter:
        options.append(f"-p {args.test_parameter}")

    # Add tamper scripts
    if args.tamper:
        options.append(f"--tamper={args.tamper}")
    elif args.auto_tamper and config.sqlmap.enable_tamper_scripts:
        # This would be enhanced by WAF detection
        options.append("--tamper=between,randomcase,charencode")
    
    # Aggressive mode
    if args.aggressive:
        options.extend(["--risk=3", "--level=5"])
    
    # Stealth mode
    if args.stealth:
        options.extend(["--time-sec=5", "--threads=1", "--delay=2"])
    
    # Random agent
    if args.random_agent:
        options.append("--random-agent")
    
    return options


def run_enhanced_adaptive_mode(runner, target_url, user_timeout, interactive_mode, args):
    """Run enhanced adaptive mode with AI integration"""
    print_info("Starting enhanced adaptive testing sequence...")
    print_info("This mode integrates AI analysis and advanced evasion techniques")

    # Get test parameter if specified
    test_param = getattr(args, 'test_parameter', None)

    # Run base adaptive testing
    result = run_adaptive_test_sequence(
        runner=runner,
        target_url=target_url,
        interactive_mode=interactive_mode,
        timeout=user_timeout,
        test_parameter=test_param
    )
    
    # Enhance with AI analysis if available
    if result and not args.disable_ai:
        try:
            asyncio.run(enhance_with_ai_analysis(result, target_url, args))
        except Exception as e:
            print_warning(f"AI analysis failed: {e}")
    
    return result


def run_enhanced_standard_mode(runner, target_url, user_timeout, interactive_mode, args):
    """Run enhanced standard mode"""
    print_info("Starting enhanced standard testing...")
    
    # Determine AI provider from arguments
    ai_provider = None
    if hasattr(args, 'ai_provider') and args.ai_provider and args.ai_provider != 'auto':
        ai_provider = args.ai_provider
        
        # Enable Ollama if selected
        if ai_provider == 'ollama':
            import os
            os.environ['ENABLE_OLLAMA'] = 'true'
            # Reinitialize AI manager to include Ollama provider
            ai_manager.reinitialize_providers()
    
    # Set Ollama model if specified
    if hasattr(args, 'ollama_model') and args.ollama_model:
        import os
        os.environ['OLLAMA_MODEL'] = args.ollama_model
    
    # Set Ollama model if specified
    if hasattr(args, 'ollama_model') and args.ollama_model:
        import os
        os.environ['OLLAMA_MODEL'] = args.ollama_model
        # Update the Ollama provider's model if it exists
        if AIProvider.OLLAMA in ai_manager.providers:
            ai_manager.providers[AIProvider.OLLAMA].update_model(args.ollama_model)
    
    # Use the existing standard mode but with enhancements
    return run_standard_mode(runner, target_url, user_timeout, interactive_mode, ai_provider, args)


async def enhance_with_ai_analysis(result, target_url, args):
    """Enhance scan results with AI analysis"""
    if not result:
        return
    
    print_info("Enhancing results with AI analysis...")
    
    # Determine AI provider from arguments
    ai_provider = None
    if hasattr(args, 'ai_provider') and args.ai_provider and args.ai_provider != 'auto':
        ai_provider = args.ai_provider
        
        # Enable Ollama if selected
        if ai_provider == 'ollama':
            import os
            os.environ['ENABLE_OLLAMA'] = 'true'
            # Reinitialize AI manager to include Ollama provider
            ai_manager.reinitialize_providers()
    
    # Set Ollama model if specified
    if hasattr(args, 'ollama_model') and args.ollama_model:
        import os
        os.environ['OLLAMA_MODEL'] = args.ollama_model
        # Update the Ollama provider's model if it exists
        if AIProvider.OLLAMA in ai_manager.providers:
            ai_manager.providers[AIProvider.OLLAMA].update_model(args.ollama_model)
    
    # Get AI response for advanced analysis
    scan_data = result.get('scan_history', [])
    if scan_data:
        last_scan = scan_data[-1]
        prompt = f"""
        Analyze this SQL injection scan result and provide:
        1. Risk assessment
        2. Exploitation recommendations
        3. Remediation advice
        
        Scan target: {target_url}
        Results: {last_scan.get('result', {})}
        """
        
        try:
            # Convert string provider to AIProvider enum if needed
            provider_enum = None
            if ai_provider:
                try:
                    from utils.ai_providers import AIProvider
                    provider_enum = AIProvider(ai_provider)
                except ValueError:
                    print_warning(f"Invalid AI provider: {ai_provider}")
                    return
            
            ai_response = await ai_manager.get_response(prompt, provider=provider_enum)
            if ai_response.success:
                result['ai_analysis'] = ai_response.content
                print_success("AI analysis completed")
        except Exception as e:
            print_warning(f"AI analysis failed: {e}")


def generate_enhanced_reports(result, args):
    """Generate enhanced reports with multiple formats"""
    print_info("Creating beautiful HTML report...")

    config = get_config()
    output_format = args.output_format or "html"
    output_dir = args.output_dir or "reports"

    # Ensure output directory exists
    import os
    os.makedirs(output_dir, exist_ok=True)

    try:
        timestamp = int(time.time())
        output_path = os.path.join(output_dir, f"sqlmap_report_{timestamp}.html")

        # Transform adaptive test result to report format
        scan_data = _transform_result_for_report(result, timestamp)

        report_path = report_generator.generate_comprehensive_report(
            scan_data=scan_data,
            output_format=output_format,
            output_path=output_path
        )

        if report_path:
            print_success(f"Beautiful HTML report generated: {report_path}")
            print_info("Open the HTML file in your browser to view the interactive report")
        else:
            print_warning("Failed to generate HTML report")

    except Exception as e:
        print_error(f"Report generation failed: {e}")


def _transform_result_for_report(result, timestamp):
    """Transform adaptive test result into format expected by HTML reporter"""
    # If result already has scan_info (from non-adaptive mode), return as is
    if "scan_info" in result:
        if "timestamp" not in result:
            result["timestamp"] = timestamp
        return result

    # Extract info from scan_history to build scan_info
    scan_history = result.get("scan_history", [])

    # Aggregate data from all steps
    all_vulns = set()
    all_databases = set()
    all_tables = []
    all_columns = {}
    all_techniques = set()
    all_payloads = []
    dbms = "Unknown"
    waf_detected = False
    raw_results = []

    for step in scan_history:
        step_result = step.get("result", {})

        # Collect vulnerable parameters
        vulns = step_result.get("vulnerable_parameters", [])
        all_vulns.update(vulns)

        # Collect databases
        databases = step_result.get("databases", [])
        all_databases.update(databases)

        # Collect tables
        tables = step_result.get("tables", [])
        all_tables.extend([t for t in tables if t not in all_tables])

        # Collect columns
        columns = step_result.get("columns", {})
        all_columns.update(columns)

        # Collect techniques
        techniques = step_result.get("techniques", [])
        all_techniques.update(techniques)

        # Collect payloads
        payloads = step_result.get("payloads", [])
        all_payloads.extend(payloads[:3])  # Add up to 3 payloads per step

        # Get DBMS
        if step_result.get("dbms") and step_result["dbms"] != "Unknown":
            dbms = step_result["dbms"]

        # Check WAF
        if step_result.get("waf_detected"):
            waf_detected = True

        # Collect raw result
        if step_result.get("raw_result"):
            raw_results.append(step_result["raw_result"])

    # Build scan_info structure
    scan_info = {
        "vulnerable_parameters": list(all_vulns),
        "databases": list(all_databases),
        "tables": all_tables,
        "columns": all_columns,
        "techniques": list(all_techniques),
        "payloads": all_payloads[:10],  # Limit to 10 payloads
        "dbms": dbms,
        "waf_detected": waf_detected,
        "raw_result": "\n\n---\n\n".join(raw_results),
        "os": "Unknown",
        "web_app": [],
        "url": ""
    }

    # Return in expected format
    return {
        "timestamp": timestamp,
        "scan_info": scan_info,
        "scan_history": scan_history,
        "success": result.get("success", False),
        "message": result.get("message", "")
    }


def run_adaptive_mode(runner, target_url, user_timeout, interactive_mode):
    print_info("Starting adaptive step-by-step testing sequence...")
    print_info("This mode will automatically sequence through multiple testing phases")
    result = run_adaptive_test_sequence(
        runner=runner,
        target_url=target_url,
        interactive_mode=interactive_mode,
        timeout=user_timeout
    )
    if result and result.get("success", False):
        if result.get("partial", False):
            print_warning("Adaptive testing completed with partial success.")
            print_info("Summary of findings:")
            if "databases_found" in result:
                print_success(f"Databases found: {', '.join(result['databases_found'])}")
                print_warning("However, tables could not be enumerated. This can happen when:")
                print_warning("1. The database is empty")
                print_warning("2. There are WAF/IPS protections against table enumeration")
                print_warning("3. The SQL injection vulnerability is limited in scope")
                print_info("The scan output is still saved for your reference.")
            if confirm_save_report():
                print_info("Creating detailed report with structured data...")
                base_filename = f"sqlmap_adaptive_partial_report_{int(time.time())}"
                text_filename = f"{base_filename}.txt"
                json_filename = f"{base_filename}.json"
                try:
                    report_content = "\n".join([f"{k}: {v}" for k, v in result.items() if k != "scan_history"])
                    report_content += "\n\nScan History:\n"
                    for step in result.get("scan_history", []):
                        report_content += f"\nStep: {step.get('step', 'unknown')}\n"
                        report_content += f"Command: {step.get('command', 'N/A')}\n"
                    with open(text_filename, "w") as f:
                        f.write(report_content)
                    print_success(f"Report saved to {text_filename}")
                    last_step = result.get("scan_history", [])[-1] if result.get("scan_history") else {}
                    last_result = last_step.get("result", {})
                    json_report = create_json_report(last_result, result.get("scan_history", []))
                    save_report_to_file(json_report, json_filename)
                    print_success(f"Structured JSON report saved to {json_filename}")
                    print_info("The JSON report format is optimized for AI analysis with Groq.")
                except Exception as e:
                    print_error(f"Failed to save report: {str(e)}")
        else:
            print_success("Adaptive testing completed successfully!")
            print_info("Summary of findings:")
            for step in result.get("scan_history", []):
                if "result" in step and "databases" in step["result"]:
                    if step["result"]["databases"]:
                        print_success(f"Databases found: {', '.join(step['result']['databases'])}")
            if "extracted_data" in result:
                for table, data in result["extracted_data"].items():
                    print_success(f"Data extracted from table: {table}")
                    if "columns" in data:
                        print_info(f"Columns: {', '.join(data['columns'])}")
            if confirm_save_report():
                print_info("Creating detailed report with structured data...")
                base_filename = f"sqlmap_adaptive_report_{int(time.time())}"
                text_filename = f"{base_filename}.txt"
                json_filename = f"{base_filename}.json"
                try:
                    report_content = "\n".join([f"{k}: {v}" for k, v in result.items() if k != "scan_history"])
                    report_content += "\n\nScan History:\n"
                    for step in result.get("scan_history", []):
                        report_content += f"\nStep: {step.get('step', 'unknown')}\n"
                        report_content += f"Command: {step.get('command', 'N/A')}\n"
                    with open(text_filename, "w") as f:
                        f.write(report_content)
                    print_success(f"Report saved to {text_filename}")
                    last_step = result.get("scan_history", [])[-1] if result.get("scan_history") else {}
                    last_result = last_step.get("result", {})
                    json_report = create_json_report(last_result, result.get("scan_history", []))
                    save_report_to_file(json_report, json_filename)
                    print_success(f"Structured JSON report saved to {json_filename}")
                    print_info("The JSON report format is optimized for AI analysis with Groq.")
                except Exception as e:
                    print_error(f"Failed to save report: {str(e)}")
    else:
        print_error("Adaptive testing failed. Check target URL and try again.")
        if result and "message" in result:
            print_info(f"Error: {result['message']}")
def run_standard_mode(runner, target_url, user_timeout, interactive_mode, ai_provider=None, args=None):
    print_info("Starting initial reconnaissance...")
    scan_history = []
    extracted_data = {}
    report = runner.gather_info(target_url, timeout=user_timeout, interactive=interactive_mode)
    if report:
        print_success("Initial reconnaissance completed!")
        initial_info = extract_sqlmap_info(report)
        scan_history.append({
            "step": "initial_reconnaissance",
            "command": f"sqlmap -u {target_url} --fingerprint --dbs",
            "result": initial_info
        })
        if "TIMEOUT:" in report:
            continue_scan, updated_report = handle_timeout_response(report, target_url, runner)
            if not continue_scan:
                return
            if updated_report:
                report = updated_report
                timeout_info = extract_sqlmap_info(updated_report)
                scan_history.append({
                    "step": "timeout_fallback",
                    "command": "Fallback scan after timeout",
                    "result": timeout_info
                })
        if "INTERRUPTED:" in report:
            print_warning("Scan was interrupted by user. Stopping here.")
            return
        display_report(report)
        # Determine AI provider name for display
        provider_name = "AI"
        if ai_provider:
            provider_name = ai_provider.upper()
        print_info(f"Analyzing results with {provider_name} and determining next steps...")
        # Determine if user wants advanced prompts
        use_advanced = None
        if hasattr(args, 'advanced') and args.advanced:
            use_advanced = True
        elif hasattr(args, 'simple') and args.simple:
            use_advanced = False
        
        next_options = ai_suggest_next_steps(
            report=report, 
            scan_history=scan_history,
            extracted_data=extracted_data,
            ai_provider=ai_provider,
            use_advanced=use_advanced
        )
        if next_options:
            user_options = get_user_choice(next_options)
            if user_options:
                print_info("Running follow-up scan...")
                
                # Calculate adaptive timeout based on scan complexity
                second_timeout = calculate_adaptive_timeout(user_timeout, user_options, "follow_up")
                
                print_info(f"Using adaptive timeout: {second_timeout} seconds")
                
                result = runner.run_sqlmap(target_url, user_options, timeout=second_timeout, interactive_mode=interactive_mode)
                if result and "TIMEOUT:" in result:
                    print_warning("Follow-up scan timed out.")
                    print_info("You may still get useful results from the partial scan data.")
                    print_info("Consider using less aggressive options or increasing timeout for complex scans.")
                if result:
                    print_success("Test completed successfully!")
                    followup_info = extract_sqlmap_info(result)
                    scan_history.append({
                        "step": "follow_up_scan",
                        "command": f"sqlmap -u {target_url} {user_options}",
                        "result": followup_info
                    })
                    display_report(result)
                    if (
                        followup_info.get("tables") 
                        and followup_info.get("columns")
                        and confirm_additional_step()
                    ):
                        print_info("Starting data extraction...")
                        extraction_options = f"--dump -T {','.join(followup_info['tables'][:3])}"
                        
                        # Use adaptive timeout for data extraction
                        extraction_timeout = calculate_adaptive_timeout(user_timeout, extraction_options, "data_extraction")
                        print_info(f"Using extraction timeout: {extraction_timeout} seconds")
                        
                        extraction_result = runner.run_sqlmap(
                            target_url, 
                            extraction_options, 
                            timeout=extraction_timeout,
                            interactive_mode=interactive_mode
                        )
                        if extraction_result:
                            print_success("Data extraction completed!")
                            extraction_info = extract_sqlmap_info(extraction_result)
                            scan_history.append({
                                "step": "data_extraction",
                                "command": f"sqlmap -u {target_url} {extraction_options}",
                                "result": extraction_info
                            })
                            if extraction_info.get("extracted"):
                                extracted_data.update(extraction_info["extracted"])
                            display_report(extraction_result)
                        elif extraction_result and "TIMEOUT:" in extraction_result:
                            print_warning("Data extraction timed out.")
                            print_info("Partial data may be available in the report.")
                    if confirm_save_report():
                        print_info("Creating beautiful HTML report...")
                        try:
                            # Create scan data structure
                            scan_data = {
                                "timestamp": int(time.time()),
                                "scan_info": followup_info,
                                "scan_history": scan_history
                            }
                            
                            # Generate HTML report
                            report_path = report_generator.generate_comprehensive_report(
                                scan_data=scan_data,
                                output_format="html"
                            )
                            print_success(f"Beautiful HTML report generated: {report_path}")
                            print_info("Open the HTML file in your browser to view the interactive report")
                        except Exception as e:
                            print_error(f"Failed to save report: {str(e)}")
                else:
                    print_error("Follow-up test failed. Check SQLMap output for details.")
        else:
            print_warning("No clear vulnerabilities found. Try different parameters or advanced options.")
    else:
        print_error("Initial test failed. Check target URL and try again.")
def confirm_additional_step():
    while True:
        choice = input("\nWould you like to extract data from discovered tables? (y/n): ").lower()
        if choice in ["y", "yes"]:
            return True
        elif choice in ["n", "no"]:
            return False
        else:
            print("Please answer with 'y' or 'n'.")

def extract_url_from_request_file(request_file_path: str) -> Optional[str]:
    """Extract target URL from HTTP request file"""
    try:
        with open(request_file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
        
        # Parse the first line to get the request line
        lines = content.split('\n')
        if not lines:
            return None
        
        # First line should be: METHOD /path HTTP/1.1
        request_line = lines[0].strip()
        parts = request_line.split()
        if len(parts) < 2:
            return None
        
        # Find Host header
        host = None
        for line in lines[1:]:
            if line.lower().startswith('host:'):
                host = line.split(':', 1)[1].strip()
                break
        
        if not host:
            return None
        
        # Determine protocol (default to http)
        protocol = 'https' if 'https://' in content.lower() else 'http'
        
        # Construct URL
        path = parts[1]
        if not path.startswith('/'):
            path = '/' + path
        
        return f"{protocol}://{host}{path}"
        
    except Exception as e:
        print_warning(f"Failed to extract URL from request file: {e}")
        return None

def get_target_url_from_args(args) -> Optional[str]:
    """Get target URL from either URL argument or request file"""
    if args.url:
        return args.url
    elif args.request_file:
        return extract_url_from_request_file(args.request_file)
    return None

def main_simple():
    """Simple mode - basic SQL injection testing without AI features"""
    print("🔧 SQLMap AI Simple Mode")
    print("=" * 50)
    
    # Get target URL
    target_url = input("Enter target URL (e.g., http://example.com/page.php?id=1): ").strip()
    if not target_url:
        print_error("Target URL is required")
        return
    
    # Basic validation
    if not target_url.startswith(('http://', 'https://')):
        print_error("URL must start with http:// or https://")
        return
    
    print_info(f"Target: {target_url}")
    print_info("Starting basic SQL injection scan...")
    
    try:
        # Initialize runner
        from sqlmap_ai.runner import SQLMapRunner
        runner = SQLMapRunner()
        
        # Basic scan options
        basic_options = "--batch --random-agent --level=1 --risk=1"
        
        # Run scan
        result = runner.run_sqlmap(target_url, basic_options, timeout=60, interactive_mode=False)
        
        if result:
            print_success("Scan completed!")
            print_info("Results:")
            print("-" * 30)
            
            # Extract basic info
            from sqlmap_ai.parser import extract_sqlmap_info
            scan_info = extract_sqlmap_info(result)
            
            if scan_info.get('vulnerable_parameters'):
                print_success(f"Vulnerabilities found: {len(scan_info['vulnerable_parameters'])}")
                for param in scan_info['vulnerable_parameters']:
                    print(f"  - Parameter: {param}")
            else:
                print_info("No vulnerabilities detected")
            
            if scan_info.get('dbms'):
                print_info(f"Database: {scan_info['dbms']}")
            
            if scan_info.get('databases'):
                print_info(f"Databases found: {', '.join(scan_info['databases'])}")
            
            # Ask if user wants to save results
            save_choice = input("\nSave results to file? (y/n): ").lower()
            if save_choice in ['y', 'yes']:
                timestamp = int(time.time())
                filename = f"reports/simple_scan_{timestamp}.txt"
                
                # Ensure reports directory exists
                import os
                os.makedirs("reports", exist_ok=True)
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"SQLMap AI Simple Scan Report\n")
                    f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Target: {target_url}\n")
                    f.write(f"Options: {basic_options}\n")
                    f.write("-" * 50 + "\n")
                    f.write(result)
                
                print_success(f"Results saved to: {filename}")
        else:
            print_error("Scan failed or no results obtained")
            
    except Exception as e:
        print_error(f"Error during scan: {e}")
        print_info("Try enhanced mode for more features and better error handling")

if __name__ == "__main__":
    main() 