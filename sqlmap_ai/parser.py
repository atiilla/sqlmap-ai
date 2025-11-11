import re
import json
from typing import Dict, List, Any, Optional
from sqlmap_ai.ui import print_success, print_warning, print_info, print_error
import time
def extract_sqlmap_info(output: str) -> Dict[str, Any]:
    if not output:
        return {}
    result = {
        "vulnerable_parameters": [],
        "techniques": [],
        "databases": [],
        "tables": [],
        "columns": {},
        "dbms": "Unknown",
        "os": "Unknown",
        "waf_detected": False,
        "web_app": [],
        "payloads": [],
        "raw_result": output,
        "url": ""
    }
    
    # Extract target URL
    url_pattern = r"starting @ \d+:\d+:\d+ /\d+-\d+-\d+/\s+\nURL: (https?://[^\s]+)"
    url_match = re.search(url_pattern, output)
    if url_match:
        result["url"] = url_match.group(1).strip()
    
    # Alternative URL extraction method for different formats
    if not result["url"]:
        alt_url_pattern = r"(?:testing URL|target URL): (https?://[^\s\n]+)"
        alt_url_match = re.search(alt_url_pattern, output, re.IGNORECASE)
        if alt_url_match:
            result["url"] = alt_url_match.group(1).strip()
    
    # Look for URL in command line args
    if not result["url"]:
        cmd_url_pattern = r"sqlmap(.py)? -u (?:\"|\')?(https?://[^\"\']+)(?:\"|\')?(?:\s|$)"
        cmd_url_match = re.search(cmd_url_pattern, output)
        if cmd_url_match:
            result["url"] = cmd_url_match.group(2).strip()
            
    # Check if URL has path parameter injection marker (*)
    if "*" in result["url"]:
        result["injection_type"] = "path_parameter"
    elif "--data=" in output:
        result["injection_type"] = "post_parameter"
    elif "--cookie=" in output:
        result["injection_type"] = "cookie_based" 
    elif "--headers=" in output:
        result["injection_type"] = "header_based"
    elif "--json" in output:
        result["injection_type"] = "json_body"
    elif "?" in result["url"] and "&" in result["url"]:
        result["injection_type"] = "multi_parameter"
    elif "?" in result["url"]:
        result["injection_type"] = "get_parameter"
        
    if "Connection refused" in output:
        result["error"] = "Connection refused - Target may not be reachable"
        return result
    if "unable to connect to the target URL" in output:
        result["error"] = "Unable to connect to the target URL"
        return result
    if "No parameter(s) found for testing" in output:
        result["warning"] = "No parameter(s) found for testing in the URL"
        return result
    if "WAF/IPS" in output or "firewall" in output.lower():
        result["waf_detected"] = True
        waf_match = re.search(r"WAF/IPS identified as '?([^'\r\n]+)'?", output)
        if waf_match:
            result["waf_type"] = waf_match.group(1).strip()
    dbms_match = re.search(r"back-end DBMS: ([^\r\n]+)", output)
    if dbms_match:
        result["dbms"] = dbms_match.group(1).strip()
        if "mysql" in result["dbms"].lower():
            result["techniques"].append("MySQL")
        elif "microsoft sql server" in result["dbms"].lower() or "mssql" in result["dbms"].lower():
            result["techniques"].append("MSSQL")
        elif "oracle" in result["dbms"].lower():
            result["techniques"].append("Oracle")
        elif "postgresql" in result["dbms"].lower():
            result["techniques"].append("PostgreSQL") 
        elif "sqlite" in result["dbms"].lower():
            result["techniques"].append("SQLite")
    os_match = re.search(r"web server operating system: ([^\r\n]+)", output)
    if os_match:
        result["os"] = os_match.group(1).strip()
    web_app_match = re.search(r"web application technology: ([^\r\n]+)", output)
    if web_app_match:
        tech_str = web_app_match.group(1).strip()
        result["web_app"] = [tech.strip() for tech in tech_str.split(",")]
    param_pattern = r"Parameter: ([^ ]+) \(([^)]+)\)"
    param_matches = re.findall(param_pattern, output)
    for param, method in param_matches:
        if param not in result["vulnerable_parameters"]:
            result["vulnerable_parameters"].append(param)
    payload_pattern = r"Payload: (.*?)(?=\n\n|\Z)"
    payload_matches = re.findall(payload_pattern, output, re.DOTALL)
    result["payloads"] = [payload.strip() for payload in payload_matches]
    databases_pattern = r"available databases \[\d+\]:\n(.*?)(?=\n\n|\Z)"
    databases_match = re.search(databases_pattern, output, re.DOTALL)
    if databases_match:
        db_section = databases_match.group(1)
        db_lines = db_section.strip().split('\n')
        for line in db_lines:
            db_name = re.sub(r'^\[\*\]\s+', '', line).strip()
            if db_name and db_name not in result["databases"]:
                result["databases"].append(db_name)
    tables_pattern = r"Database: ([^\s]+)\n.*?tables \[\d+\]:\n(.*?)(?=\n\n|\Z)"
    tables_matches = re.findall(tables_pattern, output, re.DOTALL)
    for db_name, tables_section in tables_matches:
        table_lines = tables_section.strip().split('\n')
        for line in table_lines:
            table_name = re.sub(r'^\[\d+\]\s+', '', line).strip()
            if table_name and table_name not in result["tables"]:
                result["tables"].append(table_name)
    columns_pattern = r"Table: ([^\s]+)\n.*?columns \[\d+\]:\n(.*?)(?=\n\n|\Z)"
    columns_matches = re.findall(columns_pattern, output, re.DOTALL)
    for table_name, columns_section in columns_matches:
        column_lines = columns_section.strip().split('\n')
        columns = []
        for line in column_lines:
            column_match = re.search(r'^\[\d+\]\s+([^\s]+)', line)
            if column_match:
                columns.append(column_match.group(1).strip())
        if columns:
            result["columns"][table_name] = columns
    result["extracted"] = extract_dumped_data(output)
    return result
def extract_dumped_data(output: str) -> Dict[str, Dict[str, Any]]:
    extracted_data = {}
    # Updated regex to handle both formats: "Database: xxx" and "[+] Database: xxx"
    table_dump_pattern = r"(?:\[\+\]\s+)?Database:\s+([^\n]+).*?(?:\[\+\]\s+)?Table:\s+([^\n]+).*?(?:\[\+\]\s+)?\[(\d+)\s+entr(?:y|ies)\].*?(\+[-+]+\+\n\|.*?\+[-+]+\+)"
    table_dumps = re.findall(table_dump_pattern, output, re.DOTALL)
    for db_name, table_name, entry_count, table_data in table_dumps:
        db_name = db_name.strip()
        table_name = table_name.strip()
        if '.' in table_name:
            key = table_name
        else:
            key = f"{db_name}.{table_name}"
        header_pattern = r"\|\s+([^|]+)"
        table_lines = table_data.split('\n')
        if len(table_lines) > 1:
            headers = re.findall(header_pattern, table_lines[1])
            columns = [h.strip() for h in headers]
            extracted_data[key] = {
                "columns": columns,
                "entry_count": int(entry_count),
                "raw_result": table_data
            }
    return extracted_data
def display_report(report: str) -> None:
    print("\n" + "=" * 50)
    print("             SQLMap SCAN RESULTS")
    print("=" * 50 + "\n")
    info = extract_sqlmap_info(report)
    if "error" in info:
        print_error(info["error"])
        return
    if "warning" in info:
        print_warning(info["warning"])
    if info["databases"]:
        print_success("Discovered Databases:")
        for db in info["databases"]:
            print(f"    → {db}")
        print()
    if info["tables"]:
        print_success("Discovered Tables:")
        for table in info["tables"]:
            print(f"    → {table}")
        print()
    if "techniques" in info and info["techniques"]:
        print_success("Injection Techniques:")
        for technique in info["techniques"]:
            print(f"    → {technique}")
        print()
    if "payloads" in info and info["payloads"]:
        print_success("Payload Examples:")
        for i, payload in enumerate(info["payloads"]):
            if i >= 3:  
                break
            formatted_payload = payload.replace('\n', ' ').strip()
            print(f"    → {formatted_payload}")
        print()
    if "vulnerable_parameters" in info and info["vulnerable_parameters"]:
        print_success("Vulnerable Parameters:")
        for param in info["vulnerable_parameters"]:
            print(f"    → {param}")
        print()
    if "extracted" in info and info["extracted"]:
        print_success("Extracted Data:")
        for table, data in info["extracted"].items():
            print(f"    → Table: {table}")
            if "columns" in data:
                print(f"      Columns: {', '.join(data['columns'])}")
        print()
    if info["waf_detected"]:
        print_warning("WAF/IPS Detection:")
        if "waf_type" in info:
            print_warning(f"    → WAF identified as: {info['waf_type']}")
        else:
            print_warning("    → Generic WAF/IPS/Firewall detected")
        print()
    if info["dbms"] != "Unknown":
        print_info("DBMS Information:")
        print(f"    → {info['dbms']}")
        print()
    if info["os"] != "Unknown":
        print_info("OS Information:")
        print(f"    → {info['os']}")
        print()
    if info["web_app"]:
        print_info("Web Application Technology:")
        for tech in info["web_app"]:
            print(f"    → {tech}")
        print()
def save_report_to_file(report: str, filename: str) -> None:
    try:
        with open(filename, 'w') as f:
            f.write(report)
        print_success(f"Report saved to {filename}")
    except Exception as e:
        print_error(f"Failed to save report: {str(e)}")
def create_json_report(info: Dict[str, Any], scan_history: List[Dict[str, Any]]) -> str:
    report = {
        "timestamp": int(time.time()),
        "scan_info": info,
        "scan_history": scan_history
    }
    try:
        return json.dumps(report, indent=2)
    except Exception as e:
        print_error(f"Failed to create JSON report: {str(e)}")
        return "{}" 