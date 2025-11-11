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
        """Find sqlmapapi.py from globally installed sqlmap."""
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
        """Start the sqlmapapi server if not already running."""
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
                sqlmap_dir = os.path.dirname(self.sqlmap_api_script)
                self.api_process = subprocess.Popen(
                    [sys.executable, self.sqlmap_api_script, "-s"],
                    cwd=sqlmap_dir,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                time.sleep(3)  # Wait for the server to start
                
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
        """Create a new scan task and return its ID."""
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

    def _start_scan(self, task_id: str, target_url: str, options: Union[List[str], str], request_file_path: Optional[str] = None) -> bool:
        """Start a scan for the specified target with given options."""
        scan_options = {
            "flushSession": True,
            "getBanner": True,
        }
        
        # Handle request file - prefer API's built-in requestFile option
        if request_file_path:
            # Use SQLMap API's built-in requestFile support
            scan_options["requestFile"] = os.path.abspath(request_file_path)
            if self.debug_mode:
                print_info(f"Using requestFile: {scan_options['requestFile']}")
        else:
            # Use target URL if no request file
            scan_options["url"] = target_url
        
        # Process options list into a dictionary
        if isinstance(options, list):
            request_file_from_options = None
            for opt in options:
                if opt.startswith("-r ") or opt.startswith("--request-file="):
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
                    scan_options["dump"] = True
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
                elif opt.startswith("-T "):
                    scan_options["tbl"] = opt[3:]
                elif opt.startswith("-C "):
                    scan_options["col"] = opt[3:]
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
                elif opt == "--https":
                    # Custom flag to force HTTPS
                    if "url" in scan_options and not scan_options["url"].startswith("https://"):
                        scan_options["url"] = scan_options["url"].replace("http://", "https://")
            
            # Handle request file found in options
            if request_file_from_options and not request_file_path:
                scan_options["requestFile"] = os.path.abspath(request_file_from_options)
                # Remove URL if using request file
                if "url" in scan_options:
                    del scan_options["url"]
                if self.debug_mode:
                    print_info(f"Using requestFile from options: {scan_options['requestFile']}")
                    
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
        """Get the status of a scan."""
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
        """Get the scan results."""
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
        """Delete a task."""
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
        """Clean up resources on exit."""
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
        """Enhanced error logging with debug support."""
        if self.debug_mode:
            print_error(f"{error_message}")
            print_error("Stack trace:")
            print_error(traceback.format_exc())
        else:
            print_error(error_message)

    def _detect_protocol(self, host: str, content: str = "") -> str:
        """Detect protocol based on host and content analysis."""
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
        """Parse HTTP headers handling multi-line continuation."""
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
        """Parse HTTP request file and extract components with improved header handling."""
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
        """Monitor the scan until it completes or times out."""
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
        """Get the scan logs."""
        try:
            response = requests.get(f"{self.api_server}/scan/{task_id}/log")
            data = response.json()
            
            if data["success"]:
                return "\n".join(entry["message"] for entry in data["log"])
            else:
                return None
        except:
            return None

    def _format_api_data(self, data: List[Dict[str, Any]]) -> str:
        """Format the API response data to a string similar to CLI output."""
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
            18: "dump",
            19: "search",
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
            entry_type = entry.get("type")
            value = entry.get("value")
            
            if entry_type == 1:  # Vulnerable parameters
                output_lines.append("[+] the following parameters are vulnerable to SQL injection:")
                for vuln in value:
                    output_lines.append(f"    Parameter: {vuln.get('parameter')} ({vuln.get('place')})")
                    if vuln.get("payload"):
                        output_lines.append(f"    Payload: {vuln.get('payload')}")
                
            elif entry_type == 2:  # DBMS
                output_lines.append(f"[+] back-end DBMS: {value}")
                
            elif entry_type == 3:  # Banner
                output_lines.append(f"[+] banner: {value}")
                
            elif entry_type == 4:  # Current user
                output_lines.append(f"[+] current user: {value}")
                
            elif entry_type == 7:  # Is DBA
                output_lines.append(f"[+] is DBA: {'yes' if value else 'no'}")
                
            elif entry_type == 12:  # Databases
                output_lines.append(f"[+] available databases [{len(value)}]:")
                for db in value:
                    output_lines.append(f"[*] {db}")
                    
            elif entry_type == 13:  # Tables
                output_lines.append(f"[+] Database: {list(value.keys())[0]}")
                tables = list(value.values())[0]
                output_lines.append(f"[+] tables [{len(tables)}]:")
                for i, table in enumerate(tables):
                    output_lines.append(f"[{i+1}] {table}")
                    
            elif entry_type == 14:  # Columns
                for db, tables in value.items():
                    output_lines.append(f"[+] Database: {db}")
                    for table, columns in tables.items():
                        output_lines.append(f"[+] Table: {table}")
                        output_lines.append(f"[+] columns [{len(columns)}]:")
                        for i, column in enumerate(columns):
                            output_lines.append(f"[{i+1}] {column}")
                            
            elif entry_type == 18:  # Dump
                for db, tables in value.items():
                    output_lines.append(f"[+] Database: {db}")
                    for table, data in tables.items():
                        output_lines.append(f"[+] Table: {table}")
                        output_lines.append(f"[+] [{len(data.get('entries', []))} entries]")
                        columns = data.get("columns", [])
                        entries = data.get("entries", [])
                        
                        # Create table header
                        header = "| " + " | ".join(columns) + " |"
                        separator = "+" + "+".join(["-" * (len(col) + 2) for col in columns]) + "+"
                        output_lines.append(separator)
                        output_lines.append(header)
                        output_lines.append(separator)
                        
                        # Add data rows
                        for entry in entries:
                            row = "| " + " | ".join(str(entry.get(col, "NULL")) for col in columns) + " |"
                            output_lines.append(row)
                        output_lines.append(separator)
            
            elif entry_type == 24:  # Common tables
                output_lines.append(f"[+] found common tables: {', '.join(value)}")
                
            elif entry_type == 25:  # Common columns
                output_lines.append(f"[+] found common columns: {', '.join(value)}")
            
            # Add more type handlers as needed
        
        return "\n".join(output_lines)

    def run_sqlmap(self, target_url: str = None, options: Union[List[str], str] = None, timeout: int = 180, 
                   interactive_mode: bool = False, request_file: str = None) -> Optional[str]:
        """Run sqlmap with API against the target URL and return the results."""
        task_id = self._create_new_task()
        if not task_id:
            return None
        
        # Handle options
        if options is None:
            options = []
        
        # Extract request file from options if present
        request_file_path = request_file
        if isinstance(options, list):
            for opt in options:
                if opt.startswith('-r '):
                    request_file_path = opt[3:].strip()
                    break
                elif opt.startswith('--request-file='):
                    request_file_path = opt.split('=', 1)[1].strip()
                    break
        elif isinstance(options, str) and ('-r ' in options or '--request-file=' in options):
            # Extract from string - this is more complex but handle basic cases
            parts = options.split()
            for i, part in enumerate(parts):
                if part == '-r' and i + 1 < len(parts):
                    request_file_path = parts[i + 1]
                    break
                elif part.startswith('--request-file='):
                    request_file_path = part.split('=', 1)[1]
                    break
        
        # Build command string for logging
        if request_file_path:
            command_str = f"sqlmap -r {request_file_path}"
        else:
            command_str = f"sqlmap -u {target_url}"
            
        if isinstance(options, list):
            # Filter out the -r option since we handle it separately
            filtered_options = [opt for opt in options if not (opt.startswith('-r ') or opt.startswith('--request-file='))]
            if filtered_options:
                command_str += " " + " ".join(filtered_options)
        elif isinstance(options, str):
            command_str += " " + options
            
        if self.debug_mode:
            print_info(f"Command: {command_str}")
            
        print_info("Scanning target...")
        
        if not self._start_scan(task_id, target_url, options, request_file_path):
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
        """Convenience method to run sqlmap with a request file."""
        return self.run_sqlmap(
            target_url=None, 
            options=options, 
            timeout=timeout, 
            interactive_mode=interactive_mode, 
            request_file=request_file_path
        )

    def gather_info(self, target_url: str, timeout: int = 120, interactive: bool = False) -> Optional[str]:
        """Run basic fingerprinting and database enumeration."""
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
        """Run with more focused options after a timeout."""
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