import json
import csv
import io
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os

class ReportGenerator:
    """Generate security reports in multiple formats"""
    
    def __init__(self, threat_logs):
        self.threat_logs = threat_logs
        
    def generate_summary_report(self, days: int = 7) -> Dict:
        """Generate a summary report of security activity"""
        
        # Get logs from the specified time period
        cutoff_date = datetime.now() - timedelta(days=days)
        
        if isinstance(self.threat_logs, list):
            recent_logs = [log for log in self.threat_logs if log.get('timestamp', datetime.min) > cutoff_date]
        else:
            # MongoDB query
            try:
                recent_logs = list(self.threat_logs.find(
                    {'timestamp': {'$gt': cutoff_date}},
                    {'_id': 0}
                ))
            except:
                recent_logs = []
        
        # Calculate statistics
        total_threats = len(recent_logs)
        
        # Group by severity
        severity_counts = {'Low': 0, 'Medium': 0, 'High': 0}
        for log in recent_logs:
            severity = log.get('severity', 'Low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Group by threat type
        threat_types = {}
        for log in recent_logs:
            threat_type = log.get('threat_type', 'Unknown')
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        # Group by user
        user_threats = {}
        for log in recent_logs:
            user = log.get('user', 'Unknown')
            if user not in user_threats:
                user_threats[user] = {'count': 0, 'max_risk': 0}
            user_threats[user]['count'] += 1
            user_threats[user]['max_risk'] = max(user_threats[user]['max_risk'], log.get('risk_score', 0))
        
        # Calculate average risk score
        avg_risk = 0
        if recent_logs:
            avg_risk = sum(log.get('risk_score', 0) for log in recent_logs) / len(recent_logs)
        
        return {
            'report_period_days': days,
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_threats': total_threats,
                'severity_distribution': severity_counts,
                'average_risk_score': round(avg_risk, 2),
                'high_risk_count': severity_counts['High'],
                'medium_risk_count': severity_counts['Medium'],
                'low_risk_count': severity_counts['Low']
            },
            'threat_types': threat_types,
            'top_users': dict(sorted(user_threats.items(), key=lambda x: x[1]['count'], reverse=True)[:10]),
            'recent_threats': recent_logs[:50]  # Last 50 threats
        }
    
    def export_to_csv(self, days: int = 7) -> str:
        """Export threat logs to CSV format"""
        
        cutoff_date = datetime.now() - timedelta(days=days)
        
        if isinstance(self.threat_logs, list):
            recent_logs = [log for log in self.threat_logs if log.get('timestamp', datetime.min) > cutoff_date]
        else:
            try:
                recent_logs = list(self.threat_logs.find(
                    {'timestamp': {'$gt': cutoff_date}},
                    {'_id': 0}
                ))
            except:
                recent_logs = []
        
        # Create CSV content
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Timestamp', 'User', 'Threat Type', 'Risk Score', 'Severity',
            'Source IP', 'Country', 'Failed Attempts', 'File Name',
            'Protocol', 'Source Port', 'Dest Port', 'Packet Size'
        ])
        
        # Write data
        for log in recent_logs:
            details = log.get('details', {})
            writer.writerow([
                log.get('timestamp', ''),
                log.get('user', 'Unknown'),
                log.get('threat_type', 'Unknown'),
                log.get('risk_score', 0),
                log.get('severity', 'Low'),
                details.get('ip_address', details.get('source_ip', 'N/A')),
                details.get('country', 'N/A'),
                details.get('failed_attempts', 'N/A'),
                details.get('filename', 'N/A'),
                details.get('protocol', 'N/A'),
                details.get('source_port', 'N/A'),
                details.get('dest_port', 'N/A'),
                details.get('packet_size', 'N/A')
            ])
        
        return output.getvalue()
    
    def export_to_json(self, days: int = 7) -> str:
        """Export threat logs to JSON format"""
        report = self.generate_summary_report(days)
        return json.dumps(report, indent=2, default=str)
    
    def generate_pdf_report_content(self, days: int = 7) -> str:
        """Generate HTML content for PDF report (can be converted to PDF)"""
        report = self.generate_summary_report(days)
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Cybersecurity Report - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .summary {{ background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .metric {{ display: inline-block; margin: 10px 20px; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: #e74c3c; }}
        .metric-label {{ font-size: 12px; color: #7f8c8d; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #3498db; color: white; }}
        .severity-high {{ color: #e74c3c; font-weight: bold; }}
        .severity-medium {{ color: #f39c12; }}
        .severity-low {{ color: #27ae60; }}
        .footer {{ margin-top: 40px; font-size: 10px; color: #95a5a6; text-align: center; }}
    </style>
</head>
<body>
    <h1>🛡️ Cybersecurity Monitoring Report</h1>
    <p><strong>Report Period:</strong> Last {days} days</p>
    <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="metric">
            <div class="metric-value">{report['summary']['total_threats']}</div>
            <div class="metric-label">Total Threats</div>
        </div>
        <div class="metric">
            <div class="metric-value">{report['summary']['high_risk_count']}</div>
            <div class="metric-label">High Risk</div>
        </div>
        <div class="metric">
            <div class="metric-value">{report['summary']['average_risk_score']}</div>
            <div class="metric-label">Avg Risk Score</div>
        </div>
    </div>
    
    <h2>Severity Distribution</h2>
    <table>
        <tr><th>Severity</th><th>Count</th><th>Percentage</th></tr>
        <tr>
            <td class="severity-high">High</td>
            <td>{report['summary']['severity_distribution']['High']}</td>
            <td>{round(report['summary']['severity_distribution']['High'] / max(report['summary']['total_threats'], 1) * 100, 1)}%</td>
        </tr>
        <tr>
            <td class="severity-medium">Medium</td>
            <td>{report['summary']['severity_distribution']['Medium']}</td>
            <td>{round(report['summary']['severity_distribution']['Medium'] / max(report['summary']['total_threats'], 1) * 100, 1)}%</td>
        </tr>
        <tr>
            <td class="severity-low">Low</td>
            <td>{report['summary']['severity_distribution']['Low']}</td>
            <td>{round(report['summary']['severity_distribution']['Low'] / max(report['summary']['total_threats'], 1) * 100, 1)}%</td>
        </tr>
    </table>
    
    <h2>Threat Types</h2>
    <table>
        <tr><th>Threat Type</th><th>Count</th></tr>
"""
        
        for threat_type, count in report['threat_types'].items():
            html_content += f"        <tr><td>{threat_type}</td><td>{count}</td></tr>\n"
        
        html_content += """    </table>
    
    <div class="footer">
        <p>Generated by AI Cybersecurity Monitoring Agent</p>
    </div>
</body>
</html>"""
        
        return html_content

# Global report generator instance
report_generator = None

def init_report_generator(threat_logs):
    """Initialize the report generator with threat logs"""
    global report_generator
    report_generator = ReportGenerator(threat_logs)
    return report_generator
