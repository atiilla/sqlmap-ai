import os
import sys
import time
import json
import requests
import subprocess
import traceback
import atexit
import shutil
from typing import List, Dict, Any, Optional, Union
from sqlmap_ai.ui import print_info, print_warning, print_error, print_success

class SQLMapAPIRunner:
    def __init__(self, debug_mode: bool = False):
        self.api_server = "http://127.0.0.1:8775"
        self.current_task_id = None
        self.debug_mode = debug_mode
        self.api_process = None

        # Find sqlmapapi.py from globally installed sqlmap
        self.sqlmap_api_script = self._find_sqlmapapi()

        if not self.sqlmap_api_script:
            print_error("sqlmap is not installed or not found in PATH.")
            print_error("Please install sqlmap globally using one of these methods:")
            print_error("  - apt install sqlmap (Debian/Ubuntu/Kali)")
            print_error("  - brew install sqlmap (macOS)")
            print_error("  - git clone https://github.com/sqlmapproject/sqlmap.git && cd sqlmap && sudo python setup.py install")
            sys.exit(1)

        if self.debug_mode:
            print_info(f"Using sqlmapapi.py from: {self.sqlmap_api_script}")

        # Register cleanup handler
        atexit.register(self._cleanup)

        # Start API server if not already running
        self._start_api_server()

    def _find_sqlmapapi(self) -> Optional[str]:
        
        # Method 1: Check if sqlmap is in PATH
        sqlmap_bin = shutil.which('sqlmap')
        if sqlmap_bin:
            # sqlmap might be a script or symlink, follow it
            sqlmap_real = os.path.realpath(sqlmap_bin)
            sqlmap_dir = os.path.dirname(sqlmap_real)

            # Check for sqlmapapi.py in the same directory
            api_script = os.path.join(sqlmap_dir, 'sqlmapapi.py')
            if os.path.exists(api_script):
                return api_script

        # Method 2: Check common installation paths
        common_paths = [
            '/usr/share/sqlmap/sqlmapapi.py',  # Debian/Ubuntu/Kali
            '/usr/local/share/sqlmap/sqlmapapi.py',  # Manual installation
            '/opt/sqlmap/sqlmapapi.py',  # Alternative location
            os.path.expanduser('~/sqlmap/sqlmapapi.py'),  # User home directory
        ]

        for path in common_paths:
            if os.path.exists(path):
                return path

        # Method 3: Try to find via python module
        try:
            result = subprocess.run(
                [sys.executable, '-c', 'import sqlmap; print(sqlmap.__file__)'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                sqlmap_module = result.stdout.strip()
                sqlmap_dir = os.path.dirname(sqlmap_module)
                api_script = os.path.join(sqlmap_dir, 'sqlmapapi.py')
                if os.path.exists(api_script):
                    return api_script
        except:
            pass

        return None

    def _start_api_server(self):
        
        try:
            # Check if the server is already running by testing task creation
            response = requests.get(f"{self.api_server}/task/new", timeout=3)
            if response.status_code == 200 and response.json().get("success"):
                print_info("SQLMap API server is already running.")
                # Clean up the test task
                test_task_id = response.json().get("taskid")
                if test_task_id:
                    try:
                        requests.get(f"{self.api_server}/task/{test_task_id}/delete", timeout=2)
                    except:
                        pass
                return
        except requests.exceptions.RequestException:
            print_info("Starting SQLMap API server...")
            try:
                # Start the API server process
                # Use 'waitress' adapter instead of default 'wsgiref' which is
                # broken on Python 3.13+ (binds port but never accepts connections)
                sqlmap_dir = os.path.dirname(self.sqlmap_api_script)
                server_cmd = [sys.executable, self.sqlmap_api_script, "-s"]
                try:
                    import waitress  # noqa: F401
                    server_cmd.extend(["--adapter", "waitress"])
                except ImportError:
                    pass  # fall back to default wsgiref
                self.api_process = subprocess.Popen(
                    server_cmd,
                    cwd=sqlmap_dir,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                time.sleep(2)  # Wait for the server to start
                
                # Verify server started successfully
                for _ in range(5):
                    try:
                        response = requests.get(f"{self.api_server}/task/new", timeout=2)
                        if response.status_code == 200 and response.json().get("success"):
                            if self.debug_mode:
                                print_info("SQLMap API server started successfully")
                            # Clean up the test task
                            test_task_id = response.json().get("taskid")
                            if test_task_id:
                                try:
                                    requests.get(f"{self.api_server}/task/{test_task_id}/delete", timeout=2)
                                except:
                                    pass
                            break
                    except requests.exceptions.RequestException:
                        time.sleep(1)
                else:
                    raise Exception("Failed to start SQLMap API server")
                    
            except Exception as e:
                self._log_error(f"Failed to start API server: {str(e)}")
                if self.api_process:
                    self.api_process.terminate()
                raise

    def _create_new_task(self) -> Optional[str]:
        
        try:
            response = requests.get(f"{self.api_server}/task/new")
            data = response.json()
            
            if data["success"]:
                task_id = data["taskid"]
                self.current_task_id = task_id
                return task_id
            else:
                print_error("Failed to create new task")
                return None
        except Exception as e:
            self._log_error(f"Error creating new task: {str(e)}")
            return None

    def _start_scan(self, task_id: str, target_url: str, options: Union[List[str], str], request_file_path: Optional[str] = None, is_log_file: bool = False) -> bool:

        scan_options = {
            "flushSession": True,
            "getBanner": True,
        }

        # Handle request file - use correct API option based on file type
        if request_file_path:
            abs_path = os.path.abspath(request_file_path)
            if is_log_file:
                # Burp XML log files use -l / logFile API option
                scan_options["logFile"] = abs_path
                if self.debug_mode:
                    print_info(f"Using logFile (Burp XML): {abs_path}")
            else:
                # Raw HTTP request files use -r / requestFile API option
                scan_options["requestFile"] = abs_path
                if self.debug_mode:
                    print_info(f"Using requestFile: {abs_path}")
        else:
            # Use target URL if no request file
            scan_options["url"] = target_url
        
        # Process options list into a dictionary
        if isinstance(options, list):
            request_file_from_options = None
            log_file_from_options = None
            skip_next = False
            for i, opt in enumerate(options):
                if skip_next:
                    skip_next = False
                    continue
                if opt == "-r" and i + 1 < len(options):
                    request_file_from_options = options[i + 1]
                    skip_next = True
                elif opt == "-l" and i + 1 < len(options):
                    log_file_from_options = options[i + 1]
                    skip_next = True
                elif opt.startswith("-r ") or opt.startswith("--request-file="):
                    # Extract request file path from options
                    if opt.startswith("-r "):
                        request_file_from_options = opt[3:].strip()
                    else:
                        request_file_from_options = opt.split("=", 1)[1].strip()
                elif opt.startswith("--batch"):
                    scan_options["batch"] = True
                elif opt.startswith("--threads="):
                    scan_options["threads"] = int(opt.split("=")[1])
                elif opt.startswith("--dbms="):
                    scan_options["dbms"] = opt.split("=")[1]
                elif opt.startswith("--level="):
                    scan_options["level"] = int(opt.split("=")[1])
                elif opt.startswith("--risk="):
                    scan_options["risk"] = int(opt.split("=")[1])
                elif opt.startswith("--technique="):
                    scan_options["technique"] = opt.split("=")[1]
                elif opt.startswith("--time-sec="):
                    scan_options["timeSec"] = int(opt.split("=")[1])
                elif opt.startswith("--tamper="):
                    scan_options["tamper"] = opt.split("=")[1]
                elif opt == "--fingerprint":
                    scan_options["getBanner"] = True
                    scan_options["getDbms"] = True
                elif opt == "--dbs":
                    scan_options["getDbs"] = True
                elif opt == "--tables":
                    scan_options["getTables"] = True
                elif opt == "--dump":
                    scan_options["dumpTable"] = True
                    # Reuse cached session for dump (skip re-testing injection)
                    scan_options["flushSession"] = False
                    scan_options.pop("getBanner", None)
                elif opt == "--identify-waf":
                    scan_options["identifyWaf"] = True
                elif opt == "--forms":
                    scan_options["forms"] = True
                elif opt == "--common-tables":
                    scan_options["getCommonTables"] = True
                elif opt == "--common-columns":
                    scan_options["getCommonColumns"] = True
                elif opt.startswith("-D "):
                    scan_options["db"] = opt[3:]
                elif opt == "-D" and i + 1 < len(options):
                    scan_options["db"] = options[i + 1]
                    skip_next = True
                elif opt.startswith("-T "):
                    scan_options["tbl"] = opt[3:]
                elif opt == "-T" and i + 1 < len(options):
                    scan_options["tbl"] = options[i + 1]
                    skip_next = True
                elif opt.startswith("-C "):
                    scan_options["col"] = opt[3:]
                elif opt == "-C" and i + 1 < len(options):
                    scan_options["col"] = options[i + 1]
                    skip_next = True
                elif opt.startswith("--data=") or opt.startswith("--data "):
                    data_value = opt.split("=")[1] if "=" in opt else opt[7:]
                    scan_options["data"] = data_value
                elif opt.startswith("--cookie=") or opt.startswith("--cookie "):
                    cookie_value = opt.split("=")[1] if "=" in opt else opt[9:]
                    scan_options["cookie"] = cookie_value
                elif opt.startswith("--headers=") or opt.startswith("--headers "):
                    headers_value = opt.split("=")[1] if "=" in opt else opt[10:]
                    scan_options["headers"] = headers_value
                elif opt == "--is-dba":
                    scan_options["isDba"] = True
                elif opt == "--current-user":
                    scan_options["getCurrentUser"] = True
                elif opt == "--privileges":
                    scan_options["getPrivileges"] = True
                elif opt == "--schema":
                    scan_options["getSchema"] = True
                elif opt == "--json":
                    # Handle JSON request format - already using JSON so just note it
                    pass
                elif opt == "--ignore-redirects":
                    scan_options["ignoreRedirects"] = True
                elif opt == "--https":
                    # Custom flag to force HTTPS
                    if "url" in scan_options and not scan_options["url"].startswith("https://"):
                        scan_options["url"] = scan_options["url"].replace("http://", "https://")
            
            # Handle request file (-r) found in options
            if request_file_from_options and not request_file_path:
                scan_options["requestFile"] = os.path.abspath(request_file_from_options)
                # Remove URL if using request file
                if "url" in scan_options:
                    del scan_options["url"]
                if self.debug_mode:
                    print_info(f"Using requestFile from options: {scan_options['requestFile']}")

            # Handle Burp log file (-l) found in options
            if log_file_from_options and not request_file_path:
                scan_options["logFile"] = os.path.abspath(log_file_from_options)
                # Remove URL if using log file
                if "url" in scan_options:
                    del scan_options["url"]
                if self.debug_mode:
                    print_info(f"Using logFile from options: {scan_options['logFile']}")
                    
        elif isinstance(options, str):
            # If options is a string, split and process the same way
            return self._start_scan(task_id, target_url, options.split(), request_file_path)

        # Set some defaults if not specified
        if "threads" not in scan_options:
            scan_options["threads"] = 5
        if "level" not in scan_options:
            scan_options["level"] = 1
        if "risk" not in scan_options:
            scan_options["risk"] = 1
        if "batch" not in scan_options:
            scan_options["batch"] = True
        # Auto-ignore redirects for request files in batch mode to avoid
        # login-page redirects making content appear "heavily dynamic"
        if "ignoreRedirects" not in scan_options:
            if "requestFile" in scan_options or "logFile" in scan_options:
                scan_options["ignoreRedirects"] = True
            
        try:
            headers = {"Content-Type": "application/json"}
            response = requests.post(
                f"{self.api_server}/scan/{task_id}/start",
                data=json.dumps(scan_options),
                headers=headers
            )
            data = response.json()
            
            if data["success"]:
                print_info(f"Scan started for task ID: {task_id}")
                return True
            else:
                print_error(f"Failed to start scan for task ID: {task_id}")
                print_error(f"Error: {data.get('message', 'Unknown error')}")
                return False
        except Exception as e:
            self._log_error(f"Error starting scan: {str(e)}")
            return False

    def _get_scan_status(self, task_id: str) -> Optional[str]:
        
        try:
            response = requests.get(f"{self.api_server}/scan/{task_id}/status")
            data = response.json()
            
            if data["success"]:
                return data["status"]
            else:
                print_error(f"Failed to get status for task ID: {task_id}")
                return None
        except Exception as e:
            self._log_error(f"Error getting scan status: {str(e)}")
            return None

    def _get_scan_data(self, task_id: str) -> Optional[Dict[str, Any]]:
        
        try:
            response = requests.get(f"{self.api_server}/scan/{task_id}/data")
            data = response.json()
            
            if data["success"]:
                return data["data"]
            else:
                print_error(f"Failed to get data for task ID: {task_id}")
                return None
        except Exception as e:
            self._log_error(f"Error getting scan data: {str(e)}")
            return None

    def _delete_task(self, task_id: str) -> bool:
        
        try:
            response = requests.get(f"{self.api_server}/task/{task_id}/delete")
            data = response.json()
            
            if data["success"]:
                print_info(f"Task {task_id} deleted successfully")
                return True
            else:
                print_error(f"Failed to delete task {task_id}")
                return False
        except Exception as e:
            self._log_error(f"Error deleting task: {str(e)}")
            return False

    def _cleanup(self):
        
        if self.api_process and self.api_process.poll() is None:
            try:
                self.api_process.terminate()
                self.api_process.wait(timeout=5)
            except:
                if self.debug_mode:
                    print_info("Force killing API server process")
                try:
                    self.api_process.kill()
                except:
                    pass

    def _log_error(self, error_message: str):
        
        if self.debug_mode:
            print_error(f"{error_message}")
            print_error("Stack trace:")
            print_error(traceback.format_exc())
        else:
            print_error(error_message)

    def _detect_protocol(self, host: str, content: str = "") -> str:
        
        # Check for explicit port 443
        if ":443" in host:
            return "https"
        
        # Check for HTTPS indicators in content
        https_indicators = [
            "https://",
            "ssl",
            "tls",
            "secure",
            ":443"
        ]
        
        if any(indicator in content.lower() for indicator in https_indicators):
            return "https"
        
        return "http"

    def _parse_multiline_headers(self, lines: List[str]) -> Dict[str, str]:
        
        headers = {}
        current_header = None
        current_value = ""
        
        for line in lines:
            # Check for continuation line (starts with whitespace)
            if line.startswith((' ', '\t')) and current_header:
                # Continuation of previous header
                current_value += " " + line.strip()
            elif ':' in line:
                # Save previous header if exists
                if current_header:
                    headers[current_header.lower()] = current_value.strip()
                
                # Start new header
                header_parts = line.split(':', 1)
                current_header = header_parts[0].strip()
                current_value = header_parts[1].strip() if len(header_parts) > 1 else ""
            
        # Save the last header
        if current_header:
            headers[current_header.lower()] = current_value.strip()
            
        return headers

    def _parse_request_file(self, request_file_path: str) -> Optional[Dict[str, Any]]:
        
        try:
            with open(request_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.split('\n')
            if not lines:
                return None
            
            # Parse request line (METHOD /path HTTP/1.1)
            request_line = lines[0].strip()
            parts = request_line.split()
            if len(parts) < 2:
                return None
            
            method = parts[0]
            path = parts[1]
            
            # Find headers section (skip empty lines after request line)
            header_start = 1
            while header_start < len(lines) and not lines[header_start].strip():
                header_start += 1
            
            # Find end of headers (empty line or end of file)
            header_end = header_start
            while header_end < len(lines) and lines[header_end].strip():
                header_end += 1
            
            # Parse headers with multiline support
            header_lines = lines[header_start:header_end]
            headers = self._parse_multiline_headers(header_lines)
            
            # Extract host
            host = headers.get('host', '')
            if not host:
                return None
            
            # Detect protocol
            protocol = self._detect_protocol(host, content)
            
            # Extract body if present
            body = ""
            if header_end < len(lines):
                body_lines = lines[header_end + 1:]  # Skip empty line after headers
                body = '\n'.join(body_lines).strip()
            
            # Construct URL
            if not path.startswith('/'):
                path = '/' + path
            
            url = f"{protocol}://{host}{path}"
            
            return {
                'url': url,
                'method': method,
                'headers': headers,
                'body': body,
                'protocol': protocol,
                'host': host,
                'path': path
            }
            
        except Exception as e:
            self._log_error(f"Failed to parse request file: {str(e)}")
            return None

    def _monitor_scan(self, task_id: str, timeout: int = 120, interactive_mode: bool = False) -> Optional[str]:
        
        start_time = time.time()
        last_output_time = start_time
        spinner_chars = ['|', '/', '-', '\\']
        spinner_idx = 0
        last_spinner_update = time.time()
        spinner_interval = 0.2
        last_progress_message = ""
        # Reduced refresh interval for more fluid feedback
        log_refresh_interval = 2.5 if interactive_mode else 5
        
        print_info("Starting SQLMap scan...")
        print_info("Running", end='', flush=True)
        
        try:
            while True:
                current_time = time.time()
                if current_time - last_spinner_update >= spinner_interval:
                    print(f"\b{spinner_chars[spinner_idx]}", end='', flush=True)
                    spinner_idx = (spinner_idx + 1) % len(spinner_chars)
                    last_spinner_update = current_time
                
                elapsed_time = current_time - start_time
                
                if elapsed_time > timeout:
                    print("\b \nSQLMap command timeout after {:.1f} seconds".format(elapsed_time))
                    print_warning(f"SQLMap command timeout after {elapsed_time:.1f} seconds")
                    return "TIMEOUT: Command execution exceeded time limit"
                
                status = self._get_scan_status(task_id)
                
                if status == "running":
                    # More frequent log updates for better user experience
                    if interactive_mode and current_time - last_output_time > log_refresh_interval:
                        log_data = self._get_scan_logs(task_id)
                        if log_data:
                            last_lines = log_data.splitlines()[-5:]
                            for line in last_lines:
                                if line and line != last_progress_message:
                                    print("\b \b", end='', flush=True)
                                    print(f"\r\033[K{line}")
                                    print("Running", end='', flush=True)
                                    last_progress_message = line
                        last_output_time = current_time
                    time.sleep(1)
                    continue
                elif status == "terminated":
                    print("\b \nScan completed")
                    break
                else:
                    print(f"\b \nUnexpected status: {status}")
                    break
                
                time.sleep(0.5)
            
            print("\b \b", end='', flush=True)
            print()  # New line after spinner
            
            # Get the results
            result_data = self._get_scan_data(task_id)
            if result_data is None:
                return None

            # Convert API response to a format similar to CLI output
            # Empty list means scan completed successfully but found no vulnerabilities
            if not result_data:
                return "[*] No vulnerabilities detected\n"

            formatted_output = self._format_api_data(result_data)
            return formatted_output
            
        except KeyboardInterrupt:
            print("\b \b", end='', flush=True)
            print("\nProcess interrupted by user")
            print_warning("\nProcess interrupted by user")
            return "INTERRUPTED: Process was stopped by user"
        except Exception as e:
            print("\b \b", end='', flush=True)
            self._log_error(f"Error monitoring scan: {str(e)}")
            return None

    def _get_scan_logs(self, task_id: str) -> Optional[str]:
        
        try:
            response = requests.get(f"{self.api_server}/scan/{task_id}/log")
            data = response.json()
            
            if data["success"]:
                return "\n".join(entry["message"] for entry in data["log"])
            else:
                return None
        except:
            return None

    @staticmethod
    def _ensure_list(value):
        """Safely convert a value to a list if it's a string representation."""
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, list):
                    return parsed
            except (json.JSONDecodeError, ValueError):
                pass
            try:
                import ast
                parsed = ast.literal_eval(value)
                if isinstance(parsed, list):
                    return parsed
            except (ValueError, SyntaxError):
                pass
            return [value]
        return [value] if value is not None else []

    @staticmethod
    def _ensure_dict(value):
        """Safely convert a value to a dict if it's a string representation."""
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, ValueError):
                pass
            try:
                import ast
                parsed = ast.literal_eval(value)
                if isinstance(parsed, dict):
                    return parsed
            except (ValueError, SyntaxError):
                pass
        return None

    def _format_api_data(self, data: List[Dict[str, Any]]) -> str:

        output_lines = []

        # Map of API data types to formatted sections
        type_map = {
            1: "vulnerable parameters",
            2: "back-end DBMS",
            3: "banner",
            4: "current user",
            5: "current database",
            6: "hostname",
            7: "is DBA",
            8: "users",
            9: "passwords",
            10: "privileges",
            11: "roles",
            12: "databases",
            13: "tables",
            14: "columns",
            15: "schema",
            16: "count",
            17: "dump table",
            18: "search",
            19: "sql query",
            20: "SQL query",
            21: "common tables",
            22: "common columns",
            23: "file read",
            24: "file write",
            25: "os cmd",
            26: "reg key",
            27: "reg value",
            28: "reg data",
            29: "reg enum"
        }
        
        # Process each data entry by type
        for entry in data:
            if not isinstance(entry, dict):
                continue
            entry_type = entry.get("type")
            value = entry.get("value")
            
            if entry_type == 1:  # Vulnerable parameters
                output_lines.append("[+] the following parameters are vulnerable to SQL injection:")
                vuln_list = self._ensure_list(value)
                for vuln in vuln_list:
                    if isinstance(vuln, dict):
                        output_lines.append(f"    Parameter: {vuln.get('parameter')} ({vuln.get('place')})")
                        if vuln.get("payload"):
                            output_lines.append(f"    Payload: {vuln.get('payload')}")
                    elif isinstance(vuln, str):
                        # Try to parse string repr of dict
                        parsed = self._ensure_dict(vuln)
                        if parsed and isinstance(parsed, dict) and parsed.get('parameter'):
                            output_lines.append(f"    Parameter: {parsed.get('parameter')} ({parsed.get('place')})")
                            if parsed.get("payload"):
                                output_lines.append(f"    Payload: {parsed.get('payload')}")
                        else:
                            output_lines.append(f"    {vuln}")
                
            elif entry_type == 2:  # DBMS
                output_lines.append(f"[+] back-end DBMS: {value}")
                
            elif entry_type == 3:  # Banner
                output_lines.append(f"[+] banner: {value}")
                
            elif entry_type == 4:  # Current user
                output_lines.append(f"[+] current user: {value}")
                
            elif entry_type == 7:  # Is DBA
                output_lines.append(f"[+] is DBA: {'yes' if value else 'no'}")
                
            elif entry_type == 12:  # Databases
                db_list = self._ensure_list(value)
                output_lines.append(f"[+] available databases [{len(db_list)}]:")
                for db in db_list:
                    output_lines.append(f"[*] {db}")
                    
            elif entry_type == 13:  # Tables
                value_dict = self._ensure_dict(value)
                if value_dict:
                    for db_name, table_list in value_dict.items():
                        output_lines.append(f"[+] Database: {db_name}")
                        tbl_list = self._ensure_list(table_list)
                        output_lines.append(f"[+] tables [{len(tbl_list)}]:")
                        for i, table in enumerate(tbl_list):
                            output_lines.append(f"[{i+1}] {table}")
                else:
                    output_lines.append(f"[+] tables: {value}")

            elif entry_type == 14:  # Columns
                value_dict = self._ensure_dict(value)
                if value_dict:
                    for db, tables in value_dict.items():
                        output_lines.append(f"[+] Database: {db}")
                        tables_dict = self._ensure_dict(tables) if not isinstance(tables, dict) else tables
                        if tables_dict:
                            for table, columns in tables_dict.items():
                                output_lines.append(f"[+] Table: {table}")
                                col_list = self._ensure_list(columns)
                                output_lines.append(f"[+] columns [{len(col_list)}]:")
                                for i, column in enumerate(col_list):
                                    output_lines.append(f"[{i+1}] {column}")
                else:
                    output_lines.append(f"[+] columns: {value}")

            elif entry_type == 17:  # Dump table (CONTENT_TYPE.DUMP_TABLE)
                # sqlmap API returns column-oriented data:
                # {"__infos__": {"db": "x", "table": "y", "count": N},
                #  "col1": {"length": L, "values": [...]}, ...}
                value_dict = self._ensure_dict(value)
                if value_dict:
                    infos = value_dict.get("__infos__", {})
                    db = infos.get("db", "unknown")
                    table = infos.get("table", "unknown")
                    count = infos.get("count", 0)

                    output_lines.append(f"[+] Database: {db}")
                    output_lines.append(f"[+] Table: {table}")
                    output_lines.append(f"[+] [{count} entries]")

                    # Extract column names (skip __infos__)
                    columns = [k for k in value_dict.keys() if k != "__infos__"]
                    if columns and count > 0:
                        # Calculate column widths for ASCII table
                        col_widths = {}
                        for col in columns:
                            col_data = value_dict[col]
                            values = col_data.get("values", []) if isinstance(col_data, dict) else []
                            max_val_len = max((len(str(v)) for v in values), default=0)
                            col_widths[col] = max(len(col), max_val_len)

                        # Build ASCII table
                        separator = "+" + "+".join("-" * (col_widths[c] + 2) for c in columns) + "+"
                        header = "| " + " | ".join(c.ljust(col_widths[c]) for c in columns) + " |"
                        output_lines.append(separator)
                        output_lines.append(header)
                        output_lines.append(separator)

                        for i in range(count):
                            cells = []
                            for col in columns:
                                col_data = value_dict[col]
                                values = col_data.get("values", []) if isinstance(col_data, dict) else []
                                cell_val = str(values[i]) if i < len(values) else "NULL"
                                cells.append(cell_val.ljust(col_widths[col]))
                            output_lines.append("| " + " | ".join(cells) + " |")
                        output_lines.append(separator)
                else:
                    output_lines.append(f"[+] dump: {value}")
            
            elif entry_type == 24:  # Common tables
                table_list = self._ensure_list(value)
                output_lines.append(f"[+] found common tables: {', '.join(str(t) for t in table_list)}")

            elif entry_type == 25:  # Common columns
                col_list = self._ensure_list(value)
                output_lines.append(f"[+] found common columns: {', '.join(str(c) for c in col_list)}")
            
            # Add more type handlers as needed
        
        return "\n".join(output_lines)

    def run_sqlmap(self, target_url: str = None, options: Union[List[str], str] = None, timeout: int = 180, 
                   interactive_mode: bool = False, request_file: str = None) -> Optional[str]:
        
        task_id = self._create_new_task()
        if not task_id:
            return None
        
        # Handle options
        if options is None:
            options = []
        
        # Extract request file from options if present
        request_file_path = request_file
        is_log_file = False  # True for Burp XML (-l), False for raw HTTP (-r)
        if isinstance(options, list):
            for i, opt in enumerate(options):
                if opt == '-r' and i + 1 < len(options):
                    request_file_path = options[i + 1]
                    is_log_file = False
                    break
                elif opt.startswith('-r '):
                    request_file_path = opt[3:].strip()
                    is_log_file = False
                    break
                elif opt == '-l' and i + 1 < len(options):
                    request_file_path = options[i + 1]
                    is_log_file = True
                    break
                elif opt.startswith('--request-file='):
                    request_file_path = opt.split('=', 1)[1].strip()
                    is_log_file = False
                    break
        elif isinstance(options, str) and ('-r ' in options or '--request-file=' in options or '-l ' in options):
            # Extract from string
            parts = options.split()
            for i, part in enumerate(parts):
                if part == '-r' and i + 1 < len(parts):
                    request_file_path = parts[i + 1]
                    is_log_file = False
                    break
                elif part == '-l' and i + 1 < len(parts):
                    request_file_path = parts[i + 1]
                    is_log_file = True
                    break
                elif part.startswith('--request-file='):
                    request_file_path = part.split('=', 1)[1]
                    is_log_file = False
                    break
        
        # Build command string for logging
        if request_file_path:
            command_str = f"sqlmap -r {request_file_path}"
        else:
            command_str = f"sqlmap -u {target_url}"
            
        if isinstance(options, list):
            # Filter out the -r/-l option and its argument since we handle it separately
            filtered_options = []
            skip_next = False
            for opt in options:
                if skip_next:
                    skip_next = False
                    continue
                if opt in ('-r', '-l'):
                    skip_next = True
                    continue
                if opt.startswith('-r ') or opt.startswith('--request-file='):
                    continue
                filtered_options.append(opt)
            if filtered_options:
                command_str += " " + " ".join(filtered_options)
        elif isinstance(options, str):
            command_str += " " + options
            
        if self.debug_mode:
            print_info(f"Command: {command_str}")
            
        print_info("Scanning target...")
        
        if not self._start_scan(task_id, target_url, options, request_file_path, is_log_file=is_log_file):
            self._delete_task(task_id)
            return None
            
        result = self._monitor_scan(task_id, timeout, interactive_mode)
        
        # Clean up task
        self._delete_task(task_id)
        
        if result:
            if not interactive_mode:
                result_lines = result.split('\n')
                if len(result_lines) > 20:
                    print("\n".join(result_lines[-20:]))
                    print_info("Showing last 20 lines of output. Full results will be analyzed.")
                else:
                    print(result)
            print_success("SQLMap execution completed")
            return result
        else:
            print_error("SQLMap execution failed")
            return None

    def run_sqlmap_with_request_file(self, request_file_path: str, options: Union[List[str], str] = None, 
                                   timeout: int = 180, interactive_mode: bool = False) -> Optional[str]:
        
        return self.run_sqlmap(
            target_url=None, 
            options=options, 
            timeout=timeout, 
            interactive_mode=interactive_mode, 
            request_file=request_file_path
        )

    def gather_info(self, target_url: str, timeout: int = 120, interactive: bool = False) -> Optional[str]:
        
        print_info("Starting initial reconnaissance...")
        
        try:
            result = self.run_sqlmap(
                target_url=target_url, 
                options=["--fingerprint", "--dbs", "--threads=5"], 
                timeout=timeout,
                interactive_mode=interactive
            )
            return result
        except Exception as e:
            print_error(f"Error running basic scan: {str(e)}")
            return None

    def fallback_options_for_timeout(self, target_url: str) -> Optional[str]:
        
        print_info("Running fallback scan...")
        
        fallback_options = [
            "--technique=BT",   
            "--level=1",        
            "--risk=1",         
            "--time-sec=1",     
            "--timeout=10",     
            "--retries=1",      
            "--threads=8",      
            "--dbs"             
        ]
        
        try:
            result = self.run_sqlmap(
                target_url=target_url, 
                options=fallback_options,
                timeout=90
            )
            return result
        except Exception as e:
            print_error(f"Error running fallback scan: {str(e)}")
            return None

# Alias for backward compatibility
SQLMapRunner = SQLMapAPIRunner 