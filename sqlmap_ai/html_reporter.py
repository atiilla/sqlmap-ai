#!/usr/bin/env python3
"""
HTML Report Generator with Tailwind CSS
Creates beautiful, interactive reports for SQLMap AI scans
"""

import json
import time
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import base64

class HTMLReporter:
    """Generate beautiful HTML reports with Tailwind CSS"""
    
    def __init__(self):
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
        
        # Ensure reports directory exists
        if not self.reports_dir.exists():
            self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Risk assessment factors
        self.risk_factors = {
            'dbms_privileges': {
                'dba': 10,
                'elevated': 8,
                'user': 6,
                'limited': 4,
                'none': 2
            },
            'data_sensitivity': {
                'pii': 10,
                'financial': 9,
                'medical': 9,
                'confidential': 7,
                'internal': 5,
                'public': 2
            },
            'exploitation_ease': {
                'trivial': 10,
                'easy': 8,
                'moderate': 6,
                'difficult': 4,
                'very_difficult': 2
            },
            'waf_presence': {
                'none': 10,
                'basic': 7,
                'advanced': 4,
                'enterprise': 2
            }
        }
    
    def assess_vulnerability_risk(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess vulnerability risk and impact"""
        
        # Determine injection type
        injection_type = self._determine_injection_type(vuln_data)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(vuln_data)
        risk_level = self._get_risk_level(risk_score)
        
        # Determine exploitation complexity
        complexity = self._assess_exploitation_complexity(vuln_data)
        
        # Calculate remediation priority
        priority = self._calculate_remediation_priority(risk_score, complexity)
        
        return {
            'parameter': vuln_data.get('parameter', 'unknown'),
            'injection_type': injection_type,
            'payload': vuln_data.get('payload', ''),
            'dbms': vuln_data.get('dbms', 'unknown'),
            'risk_level': risk_level,
            'confidence': vuln_data.get('confidence', 0.8),
            'exploitation_complexity': complexity,
            'impact_score': risk_score,
            'remediation_priority': priority
        }
    
    def _determine_injection_type(self, vuln_data: Dict[str, Any]) -> str:
        """Determine the type of SQL injection"""
        techniques = vuln_data.get('techniques', [])
        
        if 'time-based blind' in str(techniques).lower():
            return "Time-based Blind"
        elif 'boolean-based blind' in str(techniques).lower():
            return "Boolean-based Blind"
        elif 'union query' in str(techniques).lower():
            return "UNION Query"
        elif 'error-based' in str(techniques).lower():
            return "Error-based"
        elif 'stacked queries' in str(techniques).lower():
            return "Stacked Queries"
        else:
            return "SQL Injection"
    
    def _calculate_risk_score(self, vuln_data: Dict[str, Any]) -> int:
        """Calculate overall risk score"""
        base_score = 70  # Base SQL injection risk
        
        # Adjust for DBMS type
        dbms = vuln_data.get('dbms', '').lower()
        if 'mysql' in dbms or 'postgresql' in dbms:
            base_score += 10
        elif 'oracle' in dbms or 'mssql' in dbms:
            base_score += 15
        
        # Adjust for WAF detection
        if not vuln_data.get('waf_detected', False):
            base_score += 10
        
        # Adjust for confidence
        confidence = vuln_data.get('confidence', 0.8)
        base_score = int(base_score * confidence)
        
        return min(base_score, 100)
    
    def _get_risk_level(self, score: int) -> str:
        """Convert risk score to level"""
        if score >= 90:
            return "CRITICAL"
        elif score >= 70:
            return "HIGH"
        elif score >= 50:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _assess_exploitation_complexity(self, vuln_data: Dict[str, Any]) -> str:
        """Assess how difficult it is to exploit the vulnerability"""
        if vuln_data.get('waf_detected', False):
            return "Moderate"
        
        techniques = vuln_data.get('techniques', [])
        if 'union' in str(techniques).lower():
            return "Easy"
        elif 'blind' in str(techniques).lower():
            return "Moderate"
        else:
            return "Easy"
    
    def _calculate_remediation_priority(self, risk_score: int, complexity: str) -> str:
        """Calculate remediation priority"""
        if risk_score >= 90:
            return "IMMEDIATE"
        elif risk_score >= 70:
            return "HIGH"
        elif risk_score >= 50:
            return "MEDIUM"
        else:
            return "LOW"

    def generate_html_report(self, scan_data: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Generate a beautiful HTML report"""
        
        if output_path:
            html_path = Path(output_path)
        else:
            timestamp = int(time.time())
            html_path = self.reports_dir / f"sqlmap_report_{timestamp}.html"
        
        # Extract and assess vulnerabilities
        raw_vulnerabilities = scan_data.get('scan_info', {}).get('vulnerable_parameters', [])
        assessed_vulnerabilities = []
        
        for param in raw_vulnerabilities:
            vuln_data = {
                'parameter': param,
                'techniques': scan_data.get('scan_info', {}).get('techniques', []),
                'dbms': scan_data.get('scan_info', {}).get('dbms', 'Unknown'),
                'waf_detected': scan_data.get('scan_info', {}).get('waf_detected', False),
                'confidence': 0.8
            }
            assessed_vulnerabilities.append(self.assess_vulnerability_risk(vuln_data))
        
        # Extract other data
        techniques = scan_data.get('scan_info', {}).get('techniques', [])
        databases = scan_data.get('scan_info', {}).get('databases', [])
        dbms = scan_data.get('scan_info', {}).get('dbms', 'Unknown')
        raw_result = scan_data.get('scan_info', {}).get('raw_result', '')
        
        # Calculate scan summary
        scan_summary = self._generate_scan_summary(scan_data, assessed_vulnerabilities)
        
        # Generate HTML content
        html_content = self._create_html_template(
            vulnerabilities=assessed_vulnerabilities,
            techniques=techniques,
            databases=databases,
            dbms=dbms,
            raw_result=raw_result,
            scan_data=scan_data,
            scan_summary=scan_summary
        )
        
        # Write HTML file
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(html_path)
    
    def _generate_scan_summary(self, scan_data: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate scan summary statistics"""
        
        # Calculate overall risk
        if vulnerabilities:
            risk_scores = [v.get('impact_score', 0) for v in vulnerabilities]
            max_risk = max(risk_scores)
            avg_risk = sum(risk_scores) / len(risk_scores)
            
            if max_risk >= 90:
                overall_risk = "CRITICAL"
            elif max_risk >= 70:
                overall_risk = "HIGH"
            elif avg_risk >= 50:
                overall_risk = "MEDIUM"
            else:
                overall_risk = "LOW"
        else:
            overall_risk = "LOW"
        
        # Count databases
        all_databases = set()
        for step in scan_data.get('scan_history', []):
            databases = step.get('result', {}).get('databases', [])
            all_databases.update(databases)
        
        # Calculate success rate
        total_steps = len(scan_data.get('scan_history', []))
        successful_steps = sum(1 for step in scan_data.get('scan_history', [])
                             if step.get('result', {}).get('vulnerable_parameters'))
        success_rate = (successful_steps / total_steps * 100) if total_steps > 0 else 0
        
        return {
            'overall_risk': overall_risk,
            'vulnerability_count': len(vulnerabilities),
            'database_count': len(all_databases),
            'success_rate': success_rate,
            'scan_duration': scan_data.get('scan_duration', 0),
            'total_requests': total_steps
        }
    
    def _create_html_template(self, vulnerabilities: List[Dict[str, Any]], techniques: List[str], 
                            databases: List[str], dbms: str, raw_result: str, 
                            scan_data: Dict[str, Any], scan_summary: Dict[str, Any]) -> str:
        """Create the HTML template with Tailwind CSS"""
        
        # Use scan summary statistics
        total_vulns = scan_summary.get('vulnerability_count', 0)
        risk_level = scan_summary.get('overall_risk', 'LOW')
        risk_color = {
            'CRITICAL': 'red',
            'HIGH': 'red', 
            'MEDIUM': 'yellow',
            'LOW': 'green'
        }.get(risk_level, 'green')
        
        # Format timestamp
        timestamp = datetime.fromtimestamp(scan_data.get('timestamp', time.time()))
        formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQLMap AI Security Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        .gradient-bg {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        .card-hover {{
            transition: all 0.3s ease;
        }}
        .card-hover:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        }}
        .risk-high {{
            background: linear-gradient(135deg, #ff6b6b, #ee5a52);
        }}
        .risk-medium {{
            background: linear-gradient(135deg, #feca57, #ff9ff3);
        }}
        .risk-low {{
            background: linear-gradient(135deg, #48dbfb, #0abde3);
        }}
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
    <!-- Header -->
    <div class="gradient-bg text-white py-8">
        <div class="container mx-auto px-6">
            <div class="flex items-center justify-between">
                <div>
                    <h1 class="text-4xl font-bold mb-2">SQLMap AI - Next Generation SQL Injection Testing</h1>
                    <p class="text-xl opacity-90">Security Vulnerability Report</p>
                </div>
                <div class="text-right">
                    <div class="text-sm opacity-75">Generated on</div>
                    <div class="font-semibold">{formatted_time}</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Main Content -->
    <div class="container mx-auto px-6 py-8">
        <!-- Risk Summary -->
        <div class="mb-8">
            <div class="bg-white rounded-lg shadow-lg p-6 card-hover">
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-2xl font-bold text-gray-800">Risk Assessment</h2>
                    <div class="px-4 py-2 rounded-full text-white font-semibold risk-{risk_color}">
                        {risk_level} RISK
                    </div>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div class="text-center p-4 bg-red-50 rounded-lg">
                        <div class="text-2xl font-bold text-red-600">{total_vulns}</div>
                        <div class="text-sm text-gray-600">Vulnerabilities</div>
                    </div>
                    <div class="text-center p-4 bg-blue-50 rounded-lg">
                        <div class="text-2xl font-bold text-blue-600">{len(techniques)}</div>
                        <div class="text-sm text-gray-600">Injection Types</div>
                    </div>
                    <div class="text-center p-4 bg-green-50 rounded-lg">
                        <div class="text-2xl font-bold text-green-600">{scan_summary.get('database_count', 0)}</div>
                        <div class="text-sm text-gray-600">Databases Found</div>
                    </div>
                    <div class="text-center p-4 bg-purple-50 rounded-lg">
                        <div class="text-2xl font-bold text-purple-600">{scan_summary.get('success_rate', 0):.1f}%</div>
                        <div class="text-sm text-gray-600">Success Rate</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Vulnerabilities Section -->
        {self._generate_vulnerabilities_section(vulnerabilities)}
       

        <!-- Database Information -->
        {self._generate_database_section(databases, dbms, scan_data)}

        <!-- Scan History -->
        {self._generate_scan_history_section(scan_data.get('scan_history', []))}

        <!-- Raw Results -->
        {self._generate_raw_results_section(raw_result)}

        <!-- Charts Section -->
        {self._generate_charts_section(scan_data)}

        <!-- Footer -->
        <div class="mt-12 text-center text-gray-500">
            <p>Generated by SQLMap AI v2.0 - Advanced SQL Injection Testing Tool</p>
            <p class="text-sm mt-2">This report contains sensitive security information. Handle with care.</p>
        </div>
    </div>

    <script>
        // Interactive features
        document.addEventListener('DOMContentLoaded', function() {{
            // Add click handlers for expandable sections
            const expandButtons = document.querySelectorAll('.expand-btn');
            expandButtons.forEach(btn => {{
                btn.addEventListener('click', function() {{
                    const content = this.nextElementSibling;
                    const icon = this.querySelector('.expand-icon');
                    if (content.style.display === 'none' || !content.style.display) {{
                        content.style.display = 'block';
                        icon.textContent = '▼';
                    }} else {{
                        content.style.display = 'none';
                        icon.textContent = '▶';
                    }}
                }});
            }});

            // Initialize charts if Chart.js is available
            if (typeof Chart !== 'undefined') {{
                {self._generate_chart_js(scan_data)}
            }}
        }});
    </script>
</body>
</html>
        """
        
        return html
    
    def _generate_vulnerabilities_section(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate vulnerabilities section HTML"""
        if not vulnerabilities:
            return """
        <div class="mb-8">
            <div class="bg-white rounded-lg shadow-lg p-6 card-hover">
                <h2 class="text-2xl font-bold text-gray-800 mb-4">[X] No Vulnerabilities Found</h2>
                <p class="text-gray-600">Great! No SQL injection vulnerabilities were detected in this scan.</p>
            </div>
        </div>
            """
        
        vuln_items = ""
        for vuln in vulnerabilities:
            risk_color = {
                'CRITICAL': 'red',
                'HIGH': 'red',
                'MEDIUM': 'yellow',
                'LOW': 'blue'
            }.get(vuln.get('risk_level', 'LOW'), 'blue')
            
            priority_color = {
                'IMMEDIATE': 'red',
                'HIGH': 'red',
                'MEDIUM': 'yellow',
                'LOW': 'green'
            }.get(vuln.get('remediation_priority', 'LOW'), 'green')
            
            vuln_items += f"""
                <div class="bg-{risk_color}-50 border-l-4 border-{risk_color}-500 p-4 mb-4 rounded-r-lg">
                    <div class="flex items-start justify-between">
                        <div class="flex items-start">
                            <div class="flex-shrink-0">
                                <svg class="h-5 w-5 text-{risk_color}-400" viewBox="0 0 20 20" fill="currentColor">
                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                                </svg>
                            </div>
                            <div class="ml-3">
                                <h3 class="text-lg font-medium text-{risk_color}-800">Parameter: {vuln.get('parameter', 'unknown')}</h3>
                                <div class="mt-2 grid grid-cols-2 gap-4 text-sm text-{risk_color}-700">
                                    <div>
                                        <strong>Injection Type:</strong> {vuln.get('injection_type', 'Unknown')}
                                    </div>
                                    <div>
                                        <strong>DBMS:</strong> {vuln.get('dbms', 'Unknown')}
                                    </div>
                                    <div>
                                        <strong>Risk Level:</strong> {vuln.get('risk_level', 'Unknown')}
                                    </div>
                                    <div>
                                        <strong>Confidence:</strong> {vuln.get('confidence', 0.0) * 100:.1f}%
                                    </div>
                                    <div>
                                        <strong>Complexity:</strong> {vuln.get('exploitation_complexity', 'Unknown')}
                                    </div>
                                    <div>
                                        <strong>Impact Score:</strong> {vuln.get('impact_score', 0)}/100
                                    </div>
                                </div>
                                {f'''
                                <div class="mt-3 bg-gray-800 text-gray-100 p-3 rounded-lg">
                                    <div class="text-xs font-semibold text-gray-300 mb-1">Sample Injection Payload:</div>
                                    <code class="text-xs break-all">{vuln.get('payload', 'N/A')[:300]}{'' if len(vuln.get('payload', '')) <= 300 else '...'}</code>
                                </div>
                                ''' if vuln.get('payload') else ''}
                            </div>
                        </div>
                        <div class="flex-shrink-0">
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-{priority_color}-100 text-{priority_color}-800">
                                {vuln.get('remediation_priority', 'LOW')} Priority
                            </span>
                        </div>
                    </div>
                </div>
            """
        
        return f"""
        <div class="mb-8">
            <div class="bg-white rounded-lg shadow-lg p-6 card-hover">
                <h2 class="text-2xl font-bold text-red-800 mb-4">🚨 Vulnerabilities Detected</h2>
                <div class="mb-4">
                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                        {len(vulnerabilities)} vulnerable parameter(s) found
                    </span>
                </div>
                {vuln_items}
            </div>
        </div>
        """
    
    def _generate_database_section(self, databases: List[str], dbms: str, scan_data: Dict[str, Any] = None) -> str:
        """Generate database information section with tables and columns"""
        if not databases and not (scan_data and scan_data.get('scan_history')):
            return ""

        # Collect all databases and tables from scan history
        db_tables_map = {}
        db_columns_map = {}

        if scan_data:
            for step in scan_data.get('scan_history', []):
                result = step.get('result', {})
                step_databases = result.get('databases', [])
                step_tables = result.get('tables', [])
                step_columns = result.get('columns', {})

                # Associate tables with databases
                for db in step_databases:
                    if db not in db_tables_map:
                        db_tables_map[db] = []

                # Add tables found
                if step_tables:
                    # Try to find which database these tables belong to
                    for db in step_databases:
                        for table in step_tables:
                            if table not in db_tables_map.get(db, []):
                                if db not in db_tables_map:
                                    db_tables_map[db] = []
                                db_tables_map[db].append(table)

                # Add columns found
                if step_columns:
                    for table, cols in step_columns.items():
                        db_columns_map[table] = cols

        # Ensure all databases are in the map even if no tables
        for db in databases:
            if db not in db_tables_map:
                db_tables_map[db] = []

        db_items = ""
        for db in databases:
            tables = db_tables_map.get(db, [])
            table_list = ""

            if tables:
                for table in tables:
                    columns = db_columns_map.get(table, [])
                    col_count_text = f" ({len(columns)} columns)" if columns else ""
                    column_details = ""

                    if columns:
                        column_items = ", ".join(columns[:10])  # Show first 10 columns
                        if len(columns) > 10:
                            column_items += f", ... ({len(columns) - 10} more)"
                        column_details = f"""
                            <div class="ml-6 mt-1 text-xs text-gray-500">
                                Columns: {column_items}
                            </div>
                        """

                    table_list += f"""
                        <div class="ml-4 py-1">
                            <span class="text-sm text-gray-700">📊 {table}{col_count_text}</span>
                            {column_details}
                        </div>
                    """
            else:
                table_list = '<div class="ml-4 text-sm text-gray-500 italic">No tables enumerated</div>'

            db_items += f"""
                <div class="bg-blue-50 border border-blue-200 rounded-lg p-3 mb-3">
                    <div class="flex items-center mb-2">
                        <svg class="h-4 w-4 text-blue-500 mr-2" fill="currentColor" viewBox="0 0 20 20">
                            <path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"/>
                        </svg>
                        <span class="font-medium text-blue-800">{db}</span>
                        <span class="ml-2 text-xs text-blue-600">({len(tables)} tables)</span>
                    </div>
                    {table_list}
                </div>
            """

        return f"""
        <div class="mb-8">
            <div class="bg-white rounded-lg shadow-lg p-6 card-hover">
                <h2 class="text-2xl font-bold text-gray-800 mb-4">🗄️ Database Information</h2>
                <div class="mb-4">
                    <div class="bg-gray-50 rounded-lg p-4">
                        <h3 class="font-semibold text-gray-800 mb-2">DBMS Details</h3>
                        <p class="text-gray-600">{dbms}</p>
                    </div>
                </div>
                <div>
                    <h3 class="font-semibold text-gray-800 mb-3">Available Databases & Tables</h3>
                    {db_items}
                </div>
            </div>
        </div>
        """
    
    def _generate_scan_history_section(self, scan_history: List[Dict[str, Any]]) -> str:
        """Generate scan history section with detailed findings"""
        if not scan_history:
            return ""

        history_items = ""
        for i, step in enumerate(scan_history, 1):
            step_name = step.get('step', 'Unknown Step')
            command = step.get('command', '')
            result = step.get('result', {})
            vulns = result.get('vulnerable_parameters', [])
            databases = result.get('databases', [])
            tables = result.get('tables', [])
            columns = result.get('columns', {})
            payloads = result.get('payloads', [])

            # Build findings summary
            findings = []
            if vulns:
                findings.append(f'<span class="text-red-600">• {len(vulns)} vulnerable parameter(s): {", ".join(vulns)}</span>')
            if databases:
                findings.append(f'<span class="text-blue-600">• {len(databases)} database(s): {", ".join(databases[:5])}{"..." if len(databases) > 5 else ""}</span>')
            if tables:
                findings.append(f'<span class="text-green-600">• {len(tables)} table(s): {", ".join(tables[:5])}{"..." if len(tables) > 5 else ""}</span>')
            if columns:
                col_count = sum(len(cols) for cols in columns.values())
                findings.append(f'<span class="text-purple-600">• {col_count} column(s) in {len(columns)} table(s)</span>')
            if payloads:
                findings.append(f'<span class="text-yellow-600">• {len(payloads)} payload(s) tested</span>')

            findings_html = "<br>".join(findings) if findings else '<span class="text-gray-500 italic">No significant findings</span>'

            # Build payload section
            payload_html = ""
            if payloads and len(payloads) > 0:
                sample_payload = payloads[0][:200] + "..." if len(payloads[0]) > 200 else payloads[0]
                payload_html = f"""
                    <div class="mt-2 bg-yellow-50 border border-yellow-200 rounded p-2">
                        <div class="text-xs font-medium text-yellow-800 mb-1">Sample Payload:</div>
                        <code class="text-xs text-yellow-900 break-all">{sample_payload}</code>
                    </div>
                """

            history_items += f"""
                <div class="border-l-4 border-blue-500 pl-4 mb-6">
                    <div class="flex items-center mb-2">
                        <div class="bg-blue-500 text-white rounded-full w-8 h-8 flex items-center justify-center text-sm font-bold mr-3">
                            {i}
                        </div>
                        <h3 class="text-lg font-semibold text-gray-800">{step_name.replace('_', ' ').title()}</h3>
                    </div>
                    <div class="ml-11">
                        <div class="bg-gray-50 rounded-lg p-3 mb-3">
                            <div class="text-sm font-medium text-gray-700 mb-1">Command:</div>
                            <code class="text-xs bg-gray-100 px-2 py-1 rounded break-all">{command}</code>
                        </div>
                        <div class="bg-white border border-gray-200 rounded-lg p-3">
                            <div class="text-sm font-medium text-gray-700 mb-2">Findings:</div>
                            <div class="text-sm">
                                {findings_html}
                            </div>
                            {payload_html}
                        </div>
                    </div>
                </div>
            """

        return f"""
        <div class="mb-8">
            <div class="bg-white rounded-lg shadow-lg p-6 card-hover">
                <h2 class="text-2xl font-bold text-gray-800 mb-4">📋 Detailed Scan History</h2>
                <div class="space-y-4">
                    {history_items}
                </div>
            </div>
        </div>
        """
    
    def _generate_raw_results_section(self, raw_result: str) -> str:
        """Generate raw results section"""
        if not raw_result:
            return ""
        
        return f"""
        <div class="mb-8">
            <div class="bg-white rounded-lg shadow-lg p-6 card-hover">
                <h2 class="text-2xl font-bold text-gray-800 mb-4">📄 Raw Scan Results</h2>
                <button class="expand-btn mb-3 px-4 py-2 bg-gray-100 hover:bg-gray-200 rounded-lg text-sm font-medium flex items-center">
                    <span class="expand-icon mr-2">▶</span>
                    Toggle Raw Output
                </button>
                <div class="raw-content" style="display: none;">
                    <pre class="bg-gray-900 text-green-400 p-4 rounded-lg overflow-x-auto text-sm">{raw_result}</pre>
                </div>
            </div>
        </div>
        """
    
    def _generate_charts_section(self, scan_data: Dict[str, Any]) -> str:
        """Generate charts section"""
        return """
        <div class="mb-8">
            <div class="bg-white rounded-lg shadow-lg p-6 card-hover">
                <h2 class="text-2xl font-bold text-gray-800 mb-4">📊 Scan Analytics</h2>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                        <canvas id="vulnerabilityChart" width="400" height="200"></canvas>
                    </div>
                    <div>
                        <canvas id="scanProgressChart" width="400" height="200"></canvas>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _generate_chart_js(self, scan_data: Dict[str, Any]) -> str:
        """Generate Chart.js JavaScript code"""
        vulnerabilities = scan_data.get('scan_info', {}).get('vulnerable_parameters', [])
        techniques = scan_data.get('scan_info', {}).get('techniques', [])
        databases = scan_data.get('scan_info', {}).get('databases', [])
        
        return f"""
        // Vulnerability Chart
        const vulnCtx = document.getElementById('vulnerabilityChart').getContext('2d');
        new Chart(vulnCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Vulnerable', 'Secure'],
                datasets: [{{
                    data: [{len(vulnerabilities)}, {max(1, 10 - len(vulnerabilities))}],
                    backgroundColor: ['#ef4444', '#10b981'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }},
                    title: {{
                        display: true,
                        text: 'Vulnerability Status'
                    }}
                }}
            }}
        }});

        // Scan Progress Chart
        const progressCtx = document.getElementById('scanProgressChart').getContext('2d');
        new Chart(progressCtx, {{
            type: 'bar',
            data: {{
                labels: ['Parameters', 'Techniques', 'Databases'],
                datasets: [{{
                    label: 'Discovered',
                    data: [{len(vulnerabilities)}, {len(techniques)}, {len(databases)}],
                    backgroundColor: ['#3b82f6', '#8b5cf6', '#06b6d4'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        display: false
                    }},
                    title: {{
                        display: true,
                        text: 'Scan Discoveries'
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true
                    }}
                }}
            }}
        }});
        """
