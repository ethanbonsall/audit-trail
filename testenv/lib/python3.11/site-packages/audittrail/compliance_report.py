"""
Compliance report generator for audit trails.
Generates comprehensive reports for regulatory compliance.
"""

import json
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Any, List
import os

try:
    from .ledger import verify_ledger
    from .worm import get_protection_stats, get_violations
    from .timestamp import get_timestamp_statistics
    from .anomaly import get_anomaly_statistics, get_recent_anomalies
    from .signatures import get_key_metadata
    COMPLIANCE_AVAILABLE = True
except ImportError:
    COMPLIANCE_AVAILABLE = False


def generate_compliance_report(db_path: str, include_violations=True, include_anomalies=True) -> Dict[str, Any]:
    """
    Generate a comprehensive compliance report.
    
    Args:
        db_path: Path to the audit database
        include_violations: Include WORM violations
        include_anomalies: Include detected anomalies
    
    Returns:
        Dictionary containing the report
    """
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "database": db_path,
        "compliance_framework": "AuditTrail Enhanced",
        "version": "1.0"
    }
    
    # Ledger verification
    if COMPLIANCE_AVAILABLE:
        verification_result = verify_ledger(db_path, check_signatures=True, check_worm=True)
        report["ledger_verification"] = verification_result
    else:
        report["ledger_verification"] = {"status": "compliance_modules_not_available"}
    
    # WORM protection stats
    if COMPLIANCE_AVAILABLE:
        report["worm_protection"] = get_protection_stats(db_path)
        if include_violations:
            violations = get_violations(db_path, limit=100)
            report["worm_violations"] = {
                "count": len(violations),
                "recent_violations": violations[:10]  # Include top 10
            }
    
    # Timestamp statistics
    if COMPLIANCE_AVAILABLE:
        report["timestamp_statistics"] = get_timestamp_statistics()
    
    # Anomaly detection
    if COMPLIANCE_AVAILABLE and include_anomalies:
        report["anomaly_detection"] = get_anomaly_statistics()
        recent_anomalies = get_recent_anomalies(limit=20, unresolved_only=True)
        report["unresolved_anomalies"] = {
            "count": len(recent_anomalies),
            "details": recent_anomalies
        }
    
    # Digital signature info
    if COMPLIANCE_AVAILABLE:
        key_meta = get_key_metadata()
        report["digital_signatures"] = {
            "enabled": key_meta is not None,
            "key_metadata": key_meta
        }
    
    # Database stats
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        
        total_entries = cur.execute("SELECT COUNT(*) FROM ledger").fetchone()[0]
        date_range = cur.execute(
            "SELECT MIN(ts), MAX(ts) FROM ledger"
        ).fetchone()
        
        unique_users = cur.execute(
            "SELECT COUNT(DISTINCT user) FROM ledger"
        ).fetchone()[0]
        
        unique_paths = cur.execute(
            "SELECT COUNT(DISTINCT path) FROM ledger"
        ).fetchone()[0]
        
        conn.close()
        
        report["database_statistics"] = {
            "total_entries": total_entries,
            "date_range": {
                "start": date_range[0],
                "end": date_range[1]
            },
            "unique_users": unique_users,
            "unique_endpoints": unique_paths
        }
    except Exception as e:
        report["database_statistics"] = {"error": str(e)}
    
    # Compliance summary
    if COMPLIANCE_AVAILABLE:
        summary = {
            "overall_status": "COMPLIANT" if report["ledger_verification"].get("verified", False) else "NON_COMPLIANT",
            "features_enabled": {
                "hash_chain": True,
                "encryption": True,
                "digital_signatures": report["digital_signatures"]["enabled"],
                "timestamps": report.get("timestamp_statistics", {}).get("total_timestamps", 0) > 0,
                "worm_protection": report.get("worm_protection", {}).get("protected_entries", 0) > 0,
                "anomaly_detection": True
            },
            "risk_level": calculate_risk_level(report)
        }
        report["compliance_summary"] = summary
    
    return report


def calculate_risk_level(report: Dict[str, Any]) -> str:
    """
    Calculate overall risk level based on report data.
    
    Args:
        report: The compliance report
    
    Returns:
        Risk level (LOW, MEDIUM, HIGH, CRITICAL)
    """
    risk_score = 0
    
    # Ledger verification failures
    if not report.get("ledger_verification", {}).get("verified", True):
        risk_score += 50
    
    # WORM violations
    worm_violations = report.get("worm_violations", {}).get("count", 0)
    if worm_violations > 0:
        risk_score += min(worm_violations * 10, 30)
    
    # Unresolved anomalies
    unresolved = report.get("unresolved_anomalies", {}).get("count", 0)
    if unresolved > 0:
        risk_score += min(unresolved * 5, 20)
    
    # Signature failures
    sig_failures = report.get("ledger_verification", {}).get("signature_failures", 0)
    if sig_failures > 0:
        risk_score += min(sig_failures * 10, 30)
    
    # Determine risk level
    if risk_score >= 75:
        return "CRITICAL"
    elif risk_score >= 50:
        return "HIGH"
    elif risk_score >= 25:
        return "MEDIUM"
    else:
        return "LOW"


def export_report_to_json(report: Dict[str, Any], output_path: str):
    """Export compliance report to JSON file."""
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)


def export_report_to_html(report: Dict[str, Any], output_path: str):
    """Export compliance report to HTML file."""
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Compliance Report - {report['database']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .status {{ padding: 10px; border-radius: 5px; font-weight: bold; }}
        .compliant {{ background: #d4edda; color: #155724; }}
        .non-compliant {{ background: #f8d7da; color: #721c24; }}
        .risk-low {{ background: #d4edda; color: #155724; }}
        .risk-medium {{ background: #fff3cd; color: #856404; }}
        .risk-high {{ background: #f8d7da; color: #721c24; }}
        .risk-critical {{ background: #dc3545; color: white; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #007bff; color: white; }}
        .feature-enabled {{ color: green; }}
        .feature-disabled {{ color: red; }}
        .metric {{ display: inline-block; margin: 10px 20px; }}
        .metric-label {{ font-weight: bold; color: #666; }}
        .metric-value {{ font-size: 24px; color: #007bff; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Audit Trail Compliance Report</h1>
        <p><strong>Generated:</strong> {report['generated_at']}</p>
        <p><strong>Database:</strong> {report['database']}</p>
        
        <h2>Compliance Summary</h2>
        <div class="status {'compliant' if report.get('compliance_summary', {}).get('overall_status') == 'COMPLIANT' else 'non-compliant'}">
            Status: {report.get('compliance_summary', {}).get('overall_status', 'UNKNOWN')}
        </div>
        <div class="status risk-{report.get('compliance_summary', {}).get('risk_level', 'unknown').lower()}" style="margin-top: 10px;">
            Risk Level: {report.get('compliance_summary', {}).get('risk_level', 'UNKNOWN')}
        </div>
        
        <h2>Database Statistics</h2>
        <div>
            <div class="metric">
                <div class="metric-label">Total Entries</div>
                <div class="metric-value">{report.get('database_statistics', {}).get('total_entries', 'N/A')}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Unique Users</div>
                <div class="metric-value">{report.get('database_statistics', {}).get('unique_users', 'N/A')}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Unique Endpoints</div>
                <div class="metric-value">{report.get('database_statistics', {}).get('unique_endpoints', 'N/A')}</div>
            </div>
        </div>
        
        <h2>Ledger Verification</h2>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Verified</td>
                <td>{"✓ Yes" if report.get('ledger_verification', {}).get('verified') else "✗ No"}</td>
            </tr>
            <tr>
                <td>Total Entries Checked</td>
                <td>{report.get('ledger_verification', {}).get('total_entries', 'N/A')}</td>
            </tr>
            <tr>
                <td>Issues Found</td>
                <td>{report.get('ledger_verification', {}).get('issues', 0)}</td>
            </tr>
        </table>
        
        <h2>Security Features</h2>
        <table>
            <tr>
                <th>Feature</th>
                <th>Status</th>
            </tr>
"""
    
    features = report.get('compliance_summary', {}).get('features_enabled', {})
    for feature, enabled in features.items():
        status_class = "feature-enabled" if enabled else "feature-disabled"
        status_text = "✓ Enabled" if enabled else "✗ Disabled"
        html += f"""
            <tr>
                <td>{feature.replace('_', ' ').title()}</td>
                <td class="{status_class}">{status_text}</td>
            </tr>
"""
    
    html += """
        </table>
        
        <h2>WORM Protection</h2>
        <div>
            <div class="metric">
                <div class="metric-label">Protected Entries</div>
                <div class="metric-value">{}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Violations</div>
                <div class="metric-value">{}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Integrity Rate</div>
                <div class="metric-value">{:.1f}%</div>
            </div>
        </div>
        
        <h2>Anomalies</h2>
        <div>
            <div class="metric">
                <div class="metric-label">Unresolved</div>
                <div class="metric-value">{}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Last 24 Hours</div>
                <div class="metric-value">{}</div>
            </div>
        </div>
        
        <p style="margin-top: 40px; color: #666; font-size: 12px;">
            This report was automatically generated by AuditTrail Enhanced v1.0
        </p>
    </div>
</body>
</html>
""".format(
        report.get('worm_protection', {}).get('protected_entries', 0),
        report.get('worm_violations', {}).get('count', 0),
        report.get('worm_protection', {}).get('integrity_rate', 100.0),
        report.get('unresolved_anomalies', {}).get('count', 0),
        report.get('anomaly_detection', {}).get('last_24_hours', 0)
    )
    
    with open(output_path, 'w') as f:
        f.write(html)

