from utils.groq_utils import get_groq_response
from sqlmap_ai.ui import print_info, print_warning, print_success
from sqlmap_ai.parser import extract_sqlmap_info
import json
def ai_suggest_next_steps(report, scan_history=None, extracted_data=None):
    print_info("Analyzing SQLMap results with AI...")
    if not report:
        return ["--technique=BT", "--level=2", "--risk=1"]
    if report.startswith("TIMEOUT_WITH_PARTIAL_DATA:"):
        report = report[len("TIMEOUT_WITH_PARTIAL_DATA:"):]
    structured_info = extract_sqlmap_info(report)
    prompt = create_advanced_prompt(report, structured_info, scan_history, extracted_data)
    print_info("Sending detailed analysis request to Groq AI...")
    response = get_groq_response(prompt=prompt)
    if not response:
        print_warning("AI couldn't suggest options, using fallback options")
        return ["--technique=BEU", "--level=3"]
    print_success("Received AI recommendations!")
    try:
        # Try parsing JSON responses
        if "```json" in response:
            json_start = response.find("```json") + 7
            json_end = response.find("```", json_start)
            json_str = response[json_start:json_end].strip()
            recommendation = json.loads(json_str)
            if "sqlmap_options" in recommendation:
                return recommendation["sqlmap_options"]
            elif "options" in recommendation:
                return recommendation["options"]
        # Look for code blocks without json tag
        elif "```" in response:
            code_start = response.find("```") + 3
            code_end = response.find("```", code_start)
            code_block = response[code_start:code_end].strip()
            # Check if content is JSON
            try:
                recommendation = json.loads(code_block)
                if "sqlmap_options" in recommendation:
                    return recommendation["sqlmap_options"]
                elif "options" in recommendation:
                    return recommendation["options"]
            except:
                pass
                
        # Extract options from the response text
        options = []
        for line in response.split('\n'):
            line = line.strip()
            if line.startswith('--') or line.startswith('-p ') or line.startswith('-D ') or line.startswith('-T ') or \
               line.startswith('--data=') or line.startswith('--cookie=') or line.startswith('--headers=') or \
               line.startswith('--json') or line.startswith('--level=') or line.startswith('--risk='):
                options.append(line)
                
        # Check for URL path parameter injection marker
        if "*" in structured_info.get("url", "") and not any('--dbs' in opt for opt in options):
            options.append("--dbs")
    except Exception as e:
        print_warning(f"Error parsing AI response: {str(e)}")
        # Fallback to simple extraction
        options = []
        for line in response.strip().split('\n'):
            for part in line.split():
                if part.startswith('--') or part.startswith('-p ') or part.startswith('-D ') or part.startswith('-T ') or \
                   part.startswith('--data=') or part.startswith('--cookie=') or part.startswith('--headers=') or \
                   part.startswith('--json'):
                    options.append(part)
        
    # Handle SQLite specific cases
    if structured_info.get("dbms", "").lower() == "sqlite" and not any(opt for opt in options if opt.startswith('--tables')):
        options.append("--tables")

    # Handle URL path injection scenarios
    if structured_info.get("url", "") and "*" in structured_info.get("url", "") and not any('--dbs' in opt for opt in options):
        options.append("--dbs")
    
    # Handle JSON data scenarios
    if any(opt.startswith('--data=') for opt in options) and "json" in ' '.join(options).lower() and not any(opt == '--json' for opt in options):
        options.append("--json")
        
    # Filter out options that might cause issues
    valid_options = []
    for opt in options:
        if not opt.startswith('-d ') and not opt == '-d' and not opt == '--dump-all':
            valid_options.append(opt)
            
    if not valid_options and structured_info.get("dbms", "").lower() == "sqlite":
        print_info("Using SQLite-specific options as fallback")
        return ["--tables", "--dump"]
    elif not valid_options:
        print_warning("No valid options found, using fallback options based on URL type")
        # Set fallback options based on URL structure
        url = structured_info.get("url", "")
        if url:
            if "*" in url:
                return ["--technique=BT", "--level=2", "--risk=1"]
            elif "?" in url and "&" in url:
                return ["--technique=BT", "--level=3", "--risk=1"]
            else:
                return ["--technique=BEU", "--level=3", "--risk=2"]
        else:
            return ["--technique=BEU", "--level=3"]
        
    return valid_options
def create_advanced_prompt(report, structured_info, scan_history=None, extracted_data=None):
    prompt = """
    You are a SQLMap expert. You are given a SQLMap scan report and a list of previous scan steps.
    You need to suggest the next steps to take to fully enumerate the target application.

    Look at the scan report, previous steps, and any data extracted to decide the most effective next steps.
    Analyze what has been discovered so far and what remains to be explored.

    # SCAN REPORT SUMMARY:
    DBMS: {dbms}
    Vulnerable Parameters: {vulnerable_params}
    Techniques Tried: {techniques}
    Databases: {databases}  
    Tables: {tables}
    WAF Detected: {waf_detected}

    # PREVIOUS SCAN STEPS:
    {scan_history}

    # DATA EXTRACTED SO FAR:
    {extracted_data}

    # LATEST SCAN OUTPUT:
    {report_excerpt}

    Based on this information, suggest the next SQLMap options to use. Focus on:
    1. Exploiting vulnerabilities already found
    2. Extracting more database information if possible
    3. Dumping interesting tables when appropriate
    4. Using techniques that haven't been tried yet
    5. Avoiding techniques that have failed

    # DBMS-SPECIFIC GUIDELINES:
    - For SQLite databases: Use '--tables' instead of '--dbs' as SQLite doesn't support database enumeration. 
      Use '--dump -T [table_name]' to extract data from specific tables.
    - For MySQL/PostgreSQL: Use '--dbs' to enumerate databases, then '-D [db_name] --tables' to list tables.
    - For Microsoft SQL Server: Consider using '--os-shell' to attempt command execution if appropriate.

    # SQL INJECTION SCENARIOS:
    - Classic GET Parameter: For URLs like 'http://target.com/page.php?id=1', use basic options like '--dbs'
    - URL Path Parameter: For URLs like 'http://target.com/page/1/', use asterisk as injection marker (e.g., 'page/1*') and '--dbs'
    - Multiple Parameters: For URLs with multiple parameters, specify which to test with '-p' or use '--level=3' to test all
    - POST Parameter: Use '--data' or '--forms' to test POST parameters
    - Cookie-Based: Use '--cookie' to specify cookie values to test
    - Header-Based: Use '--headers' to test HTTP headers for injection
    - JSON Body: Use '--data' with JSON payload and add '--json' flag

    Return your recommendation in JSON format:
    ```json
    {{
      "sqlmap_options": ["option1", "option2", "..."]
    }}
    ```

    Each option should be a separate string in the array (e.g., "--level=3", "--risk=2").
    Be specific and concise. Don't include basic options like -u (URL) as these will be added automatically.
    """
    report_lines = report.split('\n')
    report_excerpt = '\n'.join(report_lines[-30:]) if len(report_lines) > 30 else report
    history_str = "No previous scan history available"
    if scan_history:
        history_lines = []
        for step in scan_history:
            if isinstance(step, dict):
                cmd = step.get("command", "Unknown command")
                step_name = step.get("step", "Unknown step")
                history_lines.append(f"- {step_name}: {cmd}")
        if history_lines:
            history_str = '\n'.join(history_lines)
    extracted_str = "No data extracted yet"
    if extracted_data:
        if isinstance(extracted_data, dict):
            extracted_lines = []
            for table, data in extracted_data.items():
                if isinstance(data, dict) and "columns" in data:
                    columns = ', '.join(data["columns"])
                    extracted_lines.append(f"- Table '{table}': Columns [{columns}]")
            if extracted_lines:
                extracted_str = '\n'.join(extracted_lines)
    formatted_prompt = prompt.format(
        report_excerpt=report_excerpt,
        dbms=structured_info.get("dbms", "Unknown"),
        vulnerable_params=', '.join(structured_info.get("vulnerable_parameters", [])) or "None identified",
        techniques=', '.join(structured_info.get("techniques", [])) or "None identified",
        databases=', '.join(structured_info.get("databases", [])) or "None identified",
        tables=', '.join(structured_info.get("tables", [])) or "None identified", 
        waf_detected="Yes" if structured_info.get("waf_detected", False) else "No",
        scan_history=history_str,
        extracted_data=extracted_str
    )
    
    # Add injection type information if available
    if "injection_type" in structured_info and structured_info["injection_type"]:
        injection_type = structured_info["injection_type"]
        injection_info = f"\n\n# INJECTION TYPE DETECTED: {injection_type.upper()}\n"
        
        if injection_type == "path_parameter":
            injection_info += "Path parameter injection typically requires using * as the injection marker.\n"
            injection_info += "Make sure to include '--dbs' in your recommendations.\n"
        elif injection_type == "post_parameter":
            injection_info += "POST parameter injection requires --data option.\n"
        elif injection_type == "cookie_based":
            injection_info += "Cookie-based injection requires --cookie option.\n"
        elif injection_type == "header_based":
            injection_info += "Header-based injection requires --headers option.\n"
        elif injection_type == "json_body":
            injection_info += "JSON body injection requires --data with JSON payload and --json flag.\n"
        elif injection_type == "multi_parameter":
            injection_info += "Multiple parameters detected. Consider using -p to specify which parameter to test or --level=3.\n"
            
        formatted_prompt += injection_info
    
    return formatted_prompt 
