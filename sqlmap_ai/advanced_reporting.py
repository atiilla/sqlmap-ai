import json
import time
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import base64

try:
    from jinja2 import Template, Environment, FileSystemLoader
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False

# WeasyPrint removed - using ReportLab for PDF generation
HAS_WEASYPRINT = False

# PDF generation removed - HTML reports only
HAS_REPORTLAB = False

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.offline import plot
    import pandas as pd
    HAS_PLOTLY = True
except ImportError:
    HAS_PLOTLY = False


@dataclass
class VulnerabilityDetails:
    
    parameter: str
    injection_type: str
    payload: str
    dbms: str
    risk_level: str
    confidence: float
    exploitation_complexity: str
    impact_score: int
    remediation_priority: str


@dataclass
class ScanStatistics:
    
    total_requests: int
    successful_injections: int
    false_positives: int
    scan_duration: float
    average_response_time: float
    waf_bypass_attempts: int
    success_rate: float


@dataclass
class RemediationGuidance:
    
    immediate_actions: List[str]
    long_term_fixes: List[str]
    secure_coding_practices: List[str]
    monitoring_recommendations: List[str]
    compliance_considerations: List[str]


class VulnerabilityAssessment:
    
    
    def __init__(self):
        self.risk_factors = {
            'dbms_privileges': {
                'dba': 10,
                'elevated': 8,
                'standard': 5,
                'limited': 3,
                'unknown': 6
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
    
    def assess_vulnerability(self, vuln_data: Dict[str, Any]) -> VulnerabilityDetails:
        
        
        # Determine injection type
        injection_type = self._determine_injection_type(vuln_data)
        
        # Calculate risk level
        risk_score = self._calculate_risk_score(vuln_data)
        risk_level = self._get_risk_level(risk_score)
        
        # Determine exploitation complexity
        complexity = self._assess_exploitation_complexity(vuln_data)
        
        # Calculate remediation priority
        priority = self._calculate_remediation_priority(risk_score, complexity)
        
        return VulnerabilityDetails(
            parameter=vuln_data.get('parameter', 'unknown'),
            injection_type=injection_type,
            payload=vuln_data.get('payload', ''),
            dbms=vuln_data.get('dbms', 'unknown'),
            risk_level=risk_level,
            confidence=vuln_data.get('confidence', 0.0),
            exploitation_complexity=complexity,
            impact_score=risk_score,
            remediation_priority=priority
        )
    
    def _determine_injection_type(self, vuln_data: Dict[str, Any]) -> str:
        
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
            return "Generic SQL Injection"
    
    def _calculate_risk_score(self, vuln_data: Dict[str, Any]) -> int:
        
        base_score = 60  # Base vulnerability score
        
        # Database privileges factor
        if vuln_data.get('is_dba', False):
            base_score += self.risk_factors['dbms_privileges']['dba']
        else:
            base_score += self.risk_factors['dbms_privileges']['standard']
        
        # Data access factor
        databases = vuln_data.get('databases', [])
        if any(db.lower() in ['users', 'accounts', 'customers', 'admin'] for db in databases):
            base_score += self.risk_factors['data_sensitivity']['pii']
        elif databases:
            base_score += self.risk_factors['data_sensitivity']['internal']
        
        # WAF presence factor
        if vuln_data.get('waf_detected', False):
            base_score += self.risk_factors['waf_presence']['basic']
        else:
            base_score += self.risk_factors['waf_presence']['none']
        
        # OS access factor
        if vuln_data.get('os_shell', False):
            base_score += 15
        
        return min(base_score, 100)
    
    def _get_risk_level(self, score: int) -> str:
        
        if score >= 90:
            return "CRITICAL"
        elif score >= 70:
            return "HIGH"
        elif score >= 50:
            return "MEDIUM"
        elif score >= 30:
            return "LOW"
        else:
            return "INFO"
    
    def _assess_exploitation_complexity(self, vuln_data: Dict[str, Any]) -> str:
        
        factors = 0
        
        # WAF presence increases complexity
        if vuln_data.get('waf_detected', False):
            factors += 2
        
        # Authentication requirements
        if vuln_data.get('requires_auth', False):
            factors += 1
        
        # HTTPS vs HTTP
        url = vuln_data.get('url', '')
        if url.startswith('https://'):
            factors += 1
        
        # Injection type complexity
        injection_type = self._determine_injection_type(vuln_data)
        if 'blind' in injection_type.lower():
            factors += 1
        
        if factors >= 4:
            return "Very Difficult"
        elif factors >= 3:
            return "Difficult"
        elif factors >= 2:
            return "Moderate"
        elif factors >= 1:
            return "Easy"
        else:
            return "Trivial"
    
    def _calculate_remediation_priority(self, risk_score: int, complexity: str) -> str:
        
        if risk_score >= 90:
            return "IMMEDIATE"
        elif risk_score >= 70:
            return "HIGH"
        elif risk_score >= 50 and complexity in ["Trivial", "Easy"]:
            return "HIGH"
        elif risk_score >= 50:
            return "MEDIUM"
        else:
            return "LOW"


class AdvancedReportGenerator:
    
    
    def __init__(self):
        self.vulnerability_assessor = VulnerabilityAssessment()
        self.template_dir = Path(__file__).parent / "templates"
        self.template_dir.mkdir(exist_ok=True)
        self._create_templates()
    
    def _create_templates(self):
        
        if not HAS_JINJA2:
            return
        
        # Main HTML template
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQLMap AI Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 3px solid #007bff; padding-bottom: 20px; margin-bottom: 30px; }
        .header h1 { color: #007bff; margin: 0; font-size: 2.5em; }
        .header p { color: #666; margin: 10px 0 0 0; font-size: 1.1em; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }
        .summary-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }
        .summary-card h3 { margin: 0 0 10px 0; font-size: 1.2em; }
        .summary-card .value { font-size: 2.5em; font-weight: bold; margin: 10px 0; }
        .risk-critical { background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%); }
        .risk-high { background: linear-gradient(135deg, #ff9a00 0%, #ffad00 100%); }
        .risk-medium { background: linear-gradient(135deg, #ffd200 0%, #f7931e 100%); }
        .risk-low { background: linear-gradient(135deg, #00d2ff 0%, #3a7bd5 100%); }
        .vulnerability { background: #f8f9fa; border-left: 5px solid #007bff; padding: 20px; margin: 20px 0; border-radius: 5px; }
        .vulnerability h3 { margin: 0 0 15px 0; color: #007bff; }
        .vulnerability .details { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .detail-item { background: white; padding: 10px; border-radius: 5px; border: 1px solid #e9ecef; }
        .detail-item strong { color: #495057; }
        .payload { background: #f1f3f4; padding: 10px; border-radius: 5px; font-family: 'Courier New', monospace; font-size: 0.9em; overflow-x: auto; margin: 10px 0; }
        .remediation { background: #e8f5e8; border: 1px solid #d4edda; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .remediation h3 { color: #155724; margin: 0 0 15px 0; }
        .remediation ul { margin: 10px 0; padding-left: 20px; }
        .remediation li { margin: 5px 0; }
        .chart-container { margin: 30px 0; text-align: center; }
        .footer { text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #e9ecef; color: #666; }
        .timestamp { font-size: 0.9em; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SQLMap AI Security Assessment</h1>
            <p>Comprehensive SQL Injection Vulnerability Analysis</p>
            <p class="timestamp">Generated: {{ report_time }}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card risk-{{ scan_summary.overall_risk.lower() }}">
                <h3>Overall Risk</h3>
                <div class="value">{{ scan_summary.overall_risk }}</div>
            </div>
            <div class="summary-card">
                <h3>Vulnerabilities Found</h3>
                <div class="value">{{ scan_summary.vulnerability_count }}</div>
            </div>
            <div class="summary-card">
                <h3>Databases Accessible</h3>
                <div class="value">{{ scan_summary.database_count }}</div>
            </div>
            <div class="summary-card">
                <h3>Success Rate</h3>
                <div class="value">{{ "%.1f"|format(scan_summary.success_rate) }}%</div>
            </div>
        </div>
        
        {% if vulnerabilities %}
        <h2>🚨 Vulnerability Details</h2>
        {% for vuln in vulnerabilities %}
        <div class="vulnerability">
            <h3>{{ vuln.injection_type }} in Parameter: {{ vuln.parameter }}</h3>
            <div class="details">
                <div class="detail-item">
                    <strong>Risk Level:</strong> 
                    <span style="color: {% if vuln.risk_level == 'CRITICAL' %}#dc3545{% elif vuln.risk_level == 'HIGH' %}#fd7e14{% elif vuln.risk_level == 'MEDIUM' %}#ffc107{% else %}#007bff{% endif %}">
                        {{ vuln.risk_level }}
                    </span>
                </div>
                <div class="detail-item"><strong>DBMS:</strong> {{ vuln.dbms }}</div>
                <div class="detail-item"><strong>Confidence:</strong> {{ "%.1f"|format(vuln.confidence * 100) }}%</div>
                <div class="detail-item"><strong>Complexity:</strong> {{ vuln.exploitation_complexity }}</div>
                <div class="detail-item"><strong>Priority:</strong> {{ vuln.remediation_priority }}</div>
                <div class="detail-item"><strong>Impact Score:</strong> {{ vuln.impact_score }}/100</div>
            </div>
            {% if vuln.payload %}
            <h4>Example Payload:</h4>
            <div class="payload">{{ vuln.payload }}</div>
            {% endif %}
        </div>
        {% endfor %}
        {% endif %}
        
        {% if remediation %}
        <div class="remediation">
            <h3>🔧 Remediation Guidance</h3>
            
            <h4>Immediate Actions Required:</h4>
            <ul>
                {% for action in remediation.immediate_actions %}
                <li>{{ action }}</li>
                {% endfor %}
            </ul>
            
            <h4>Long-term Security Fixes:</h4>
            <ul>
                {% for fix in remediation.long_term_fixes %}
                <li>{{ fix }}</li>
                {% endfor %}
            </ul>
            
            <h4>Secure Coding Practices:</h4>
            <ul>
                {% for practice in remediation.secure_coding_practices %}
                <li>{{ practice }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        {% if scan_history %}
        <h2>📊 Scan Timeline</h2>
        <div class="chart-container">
            {{ scan_timeline_chart|safe }}
        </div>
        {% endif %}
        
        <div class="footer">
            <p>Report generated by SQLMap AI Red Team Tool</p>
            <p>⚠️ This report contains sensitive security information - Handle with care</p>
        </div>
    </div>
</body>
</html>
        """
        
        with open(self.template_dir / "report_template.html", "w", encoding='utf-8') as f:
            f.write(html_template)
    
    def generate_comprehensive_report(
        self,
        scan_data: Dict[str, Any],
        output_format: str = "html",
        output_path: Optional[str] = None
    ) -> str:
        
        
        # Process scan data
        vulnerabilities = self._process_vulnerabilities(scan_data)
        scan_summary = self._generate_scan_summary(scan_data, vulnerabilities)
        remediation = self._generate_remediation_guidance(vulnerabilities)
        
        # Generate HTML report only
        if html_reporter:
            return html_reporter.generate_html_report(scan_data, output_path)
        else:
            return self._generate_html_report(
                scan_data, vulnerabilities, scan_summary, remediation, output_path
            )
    
    def _process_vulnerabilities(self, scan_data: Dict[str, Any]) -> List[VulnerabilityDetails]:
        
        vulnerabilities = []
        
        scan_history = scan_data.get('scan_history', [])
        for step in scan_history:
            result = step.get('result', {})
            
            if result.get('vulnerable_parameters'):
                for param in result['vulnerable_parameters']:
                    vuln_data = {
                        'parameter': param,
                        'payload': result.get('payloads', [''])[0] if result.get('payloads') else '',
                        'dbms': result.get('dbms', 'Unknown'),
                        'techniques': result.get('techniques', []),
                        'databases': result.get('databases', []),
                        'waf_detected': result.get('waf_detected', False),
                        'url': result.get('url', ''),
                        'confidence': 0.8  # Default confidence
                    }
                    
                    vuln_details = self.vulnerability_assessor.assess_vulnerability(vuln_data)
                    vulnerabilities.append(vuln_details)
        
        return vulnerabilities
    
    def _generate_scan_summary(
        self, 
        scan_data: Dict[str, Any], 
        vulnerabilities: List[VulnerabilityDetails]
    ) -> Dict[str, Any]:
        
        
        # Calculate overall risk
        if vulnerabilities:
            risk_scores = [v.impact_score for v in vulnerabilities]
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
    
    def _generate_remediation_guidance(self, vulnerabilities: List[VulnerabilityDetails]) -> RemediationGuidance:
        
        
        immediate_actions = [
            "Immediately patch or disable vulnerable endpoints",
            "Implement input validation and sanitization",
            "Review and update database access permissions",
            "Enable database query logging and monitoring"
        ]
        
        long_term_fixes = [
            "Implement parameterized queries (prepared statements)",
            "Use stored procedures with proper parameter validation",
            "Implement database connection pooling with least privilege",
            "Deploy Web Application Firewall (WAF) with SQL injection rules",
            "Conduct regular security code reviews",
            "Implement database encryption for sensitive data"
        ]
        
        secure_coding_practices = [
            "Always use parameterized queries instead of string concatenation",
            "Validate and sanitize all user inputs",
            "Use whitelisting for input validation where possible",
            "Implement proper error handling without information disclosure",
            "Follow the principle of least privilege for database access",
            "Use ORM frameworks with built-in SQL injection protection"
        ]
        
        monitoring_recommendations = [
            "Implement real-time database activity monitoring",
            "Set up alerts for suspicious SQL query patterns",
            "Monitor for unusual database access patterns",
            "Log all database connections and queries",
            "Implement intrusion detection systems (IDS)",
            "Regular vulnerability scanning and penetration testing"
        ]
        
        compliance_considerations = [
            "Ensure compliance with PCI DSS if handling payment data",
            "Follow GDPR requirements for data protection",
            "Implement SOX compliance for financial data",
            "Meet HIPAA requirements for healthcare data",
            "Document security controls for audit purposes"
        ]
        
        return RemediationGuidance(
            immediate_actions=immediate_actions,
            long_term_fixes=long_term_fixes,
            secure_coding_practices=secure_coding_practices,
            monitoring_recommendations=monitoring_recommendations,
            compliance_considerations=compliance_considerations
        )
    
    def _generate_html_report(
        self,
        scan_data: Dict[str, Any],
        vulnerabilities: List[VulnerabilityDetails],
        scan_summary: Dict[str, Any],
        remediation: RemediationGuidance,
        output_path: Optional[str] = None
    ) -> str:
        
        
        if not HAS_JINJA2:
            return self._generate_simple_html_report(scan_data, vulnerabilities, scan_summary)
        
        # Load template
        env = Environment(loader=FileSystemLoader(self.template_dir))
        template = env.get_template("report_template.html")
        
        # Generate timeline chart if plotly is available
        scan_timeline_chart = ""
        if HAS_PLOTLY:
            scan_timeline_chart = self._generate_timeline_chart(scan_data.get('scan_history', []))
        
        # Render template
        html_content = template.render(
            report_time=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            scan_summary=scan_summary,
            vulnerabilities=[asdict(v) for v in vulnerabilities],
            remediation=asdict(remediation),
            scan_history=scan_data.get('scan_history', []),
            scan_timeline_chart=scan_timeline_chart
        )
        
        # Save to file if path provided
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return output_path
        else:
            # Generate filename in reports directory
            timestamp = int(time.time())
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)
            filename = reports_dir / f"sqlmap_report_{timestamp}.html"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return str(filename)
    
    def _generate_simple_html_report(
        self,
        scan_data: Dict[str, Any],
        vulnerabilities: List[VulnerabilityDetails],
        scan_summary: Dict[str, Any]
    ) -> str:
        
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SQLMap AI Security Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ text-align: center; border-bottom: 2px solid #007bff; padding-bottom: 20px; }}
                .vulnerability {{ background: #f8f9fa; padding: 15px; margin: 15px 0; border-left: 4px solid #007bff; }}
                .risk-critical {{ border-left-color: #dc3545; }}
                .risk-high {{ border-left-color: #fd7e14; }}
                .risk-medium {{ border-left-color: #ffc107; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>SQLMap AI Security Assessment Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <h2>Summary</h2>
            <p><strong>Overall Risk:</strong> {scan_summary['overall_risk']}</p>
            <p><strong>Vulnerabilities Found:</strong> {scan_summary['vulnerability_count']}</p>
            <p><strong>Databases Accessible:</strong> {scan_summary['database_count']}</p>
            
            <h2>Vulnerabilities</h2>
        """
        
        for vuln in vulnerabilities:
            risk_class = f"risk-{vuln.risk_level.lower()}"
            html_content += f"""
            <div class="vulnerability {risk_class}">
                <h3>{vuln.injection_type} in {vuln.parameter}</h3>
                <p><strong>Risk Level:</strong> {vuln.risk_level}</p>
                <p><strong>DBMS:</strong> {vuln.dbms}</p>
                <p><strong>Complexity:</strong> {vuln.exploitation_complexity}</p>
                <p><strong>Priority:</strong> {vuln.remediation_priority}</p>
            </div>
            """
        
        html_content += """
        </body>
        </html>
        """
        
        timestamp = int(time.time())
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        filename = reports_dir / f"sqlmap_simple_report_{timestamp}.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(filename)
    

    
    def _generate_json_report(
        self,
        scan_data: Dict[str, Any],
        vulnerabilities: List[VulnerabilityDetails],
        scan_summary: Dict[str, Any],
        remediation: RemediationGuidance,
        output_path: Optional[str] = None
    ) -> str:
        
        
        report_data = {
            "metadata": {
                "report_version": "2.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "tool_version": "SQLMap AI v2.0",
                "scan_id": f"scan_{int(time.time())}"
            },
            "scan_summary": scan_summary,
            "vulnerabilities": [asdict(v) for v in vulnerabilities],
            "remediation": asdict(remediation),
            "raw_scan_data": scan_data
        }
        
        if output_path:
            json_path = output_path
        else:
            timestamp = int(time.time())
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)
            json_path = reports_dir / f"sqlmap_report_{timestamp}.json"
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        return str(json_path)
    

    
    def _generate_timeline_chart(self, scan_history: List[Dict[str, Any]]) -> str:
        
        
        if not HAS_PLOTLY:
            return ""
        
        if not scan_history:
            return ""
        
        # Prepare data
        steps = []
        durations = []
        success_indicators = []
        
        for i, step in enumerate(scan_history):
            steps.append(f"Step {i+1}: {step.get('step', 'Unknown')}")
            durations.append(step.get('duration', 1))  # Default 1 second
            
            # Determine success
            result = step.get('result', {})
            if result.get('vulnerable_parameters') or result.get('databases'):
                success_indicators.append("Success")
            else:
                success_indicators.append("No findings")
        
        # Create figure
        fig = go.Figure()
        
        # Add bars
        colors = ['#28a745' if s == "Success" else '#6c757d' for s in success_indicators]
        
        fig.add_trace(go.Bar(
            x=steps,
            y=durations,
            name="Scan Steps",
            marker_color=colors,
            text=success_indicators,
            textposition='outside'
        ))
        
        fig.update_layout(
            title="Scan Timeline and Results",
            xaxis_title="Scan Steps",
            yaxis_title="Duration (seconds)",
            height=400,
            showlegend=False
        )
        
        # Generate HTML
        return plot(fig, output_type='div', include_plotlyjs=True)


# Global report generator instance
report_generator = AdvancedReportGenerator()

# Import HTML reporter
try:
    from sqlmap_ai.html_reporter import HTMLReporter
    html_reporter = HTMLReporter()
except ImportError:
    html_reporter = None
