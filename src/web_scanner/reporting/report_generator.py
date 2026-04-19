import json
import re
from datetime import datetime
from typing import Dict, List, Union, Optional
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from .pdf_generator import ReportGenerator as PDFGenerator

def generate_report(
    scan_results: Union[Dict, List], 
    output_format: str = 'html',
    output_file: Optional[str] = None,
    template_path: Optional[str] = None
) -> str:
    """Generate a report from scan results"""
    if isinstance(scan_results, list):
        # Convert list of findings to proper report structure
        scan_data = {
            'findings': scan_results,
            'stats': {
                'total_findings': len(scan_results),
                'start_time': datetime.now().isoformat(),
                'end_time': datetime.now().isoformat(), 
                'duration': 0
            }
        }
    else:
        scan_data = dict(scan_results)

    findings = _prepare_findings(scan_data.get('findings', []))
    scan_data['findings'] = findings

    modules = scan_data.get('modules', [])
    for module in modules:
        module_findings = module.get('findings', [])
        if isinstance(module_findings, list):
            module['findings'] = _prepare_findings(module_findings)

    test_name_map = {
        'headers': 'Security Headers',
        'ssl_tls': 'SSL/TLS Configuration',
        'server_info': 'Server Information',
        'version_info': 'Version Disclosure',
        'sensitive_data': 'Sensitive Data Exposure',
        'directory_listing': 'Directory Listing',
        'xss': 'Cross-Site Scripting',
        'sql': 'SQL Injection',
        'command': 'Command Injection',
        'csrf': 'CSRF Protection',
        'session': 'Session Management',
        'auth_bypass': 'Authentication Bypass',
        'rce': 'Remote Code Execution',
        'lfi': 'Local File Inclusion',
        'xxe': 'XML External Entity',
        'deserialization': 'Deserialization'
    }

    # Process scan data into template format
    template_data = {
        'target': scan_data.get('target', 'Unknown'),
        'timestamp': scan_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
        'urls_scanned': scan_data.get('urls_scanned', 1),
        
        # Calculate test statistics
        'total_tests': sum(m.get('tests_available', 0) for m in scan_data.get('modules', [])),
        'tests_completed': sum(m.get('tests_run', 0) for m in scan_data.get('modules', [])),
        'total_findings': len(findings),
        'scan_duration': f"{scan_data.get('duration', 0):.2f}s",
        
        # Module data
        'modules': [
            {
                'name': module.get('name', ''),
                'tests_available': module.get('tests_available', 0),
                'tests_run': module.get('tests_run', 0),
                'duration': f"{module.get('duration', 0):.2f}",
                'issues_found': len(module.get('findings', []))
            }
            for module in scan_data.get('modules', [])
        ],
        
        # Individual test data
        'tests': [
            {
                'name': test_name_map.get(test_name, test_name),
                'status': 'completed',
                'duration': f"{(mod['duration']/len(mod.get('test_names',[]))):.2f}s" 
                            if len(mod.get('test_names',[])) > 0 else "0.00s",
                'issues_found': sum(
                    1 for f in mod.get('findings', []) 
                    if test_name.lower() in f.get('type','').lower()
                )
            }
            for mod in scan_data.get('modules', [])
            for test_name in mod.get('test_names', [])
        ],
        
        # Findings
        'findings': findings,
        
        # Add the test weights data
        'test_weights': {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4,
            'info': 0.2
        },
        'test_timings': scan_data.get('test_timings', {}),
        'test_issues': scan_data.get('test_issues', {}),
        'confidence_score': scan_data.get('confidence_score') or _summarize_confidence(findings)
    }

    if output_format == 'json':
        return _generate_json_report(template_data, output_file)
    elif output_format == 'pdf':
        pdf_gen = PDFGenerator()
        return pdf_gen.generate_report(template_data['findings'], template_data)
    else:
        return _generate_html_report(template_data, output_file, template_path)

def _generate_json_report(report_data: Dict, output_file: Optional[str] = None) -> str:  
    """Generate JSON format report"""
    report_content = json.dumps(report_data, indent=2, ensure_ascii=False)
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        return output_file
    return report_content

def _generate_html_report(
    report_data: Dict, 
    output_file: Optional[str] = None,
    template_path: Optional[str] = None
) -> str:
    """Generate HTML report using template"""
    # Get template directory path
    if template_path:
        template_dir = Path(template_path).parent
        template_file = Path(template_path).name
    else:
        template_dir = Path(__file__).parent / 'templates'
        template_file = 'technical_details.html'
        
    # Setup Jinja2 environment
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=True
    )
    
    # Load and render template
    template = env.get_template(template_file)
    report_content = template.render(**report_data)
    
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        return output_file
        
    return report_content

def _count_severities(findings: List[Dict]) -> Dict[str, int]:
    """Count findings by severity level"""
    counts = {}
    for finding in findings:
        severity = finding.get('severity', 'Unknown')
        counts[severity] = counts.get(severity, 0) + 1
    return counts

def _normalize_text(value: Optional[str]) -> str:
    return re.sub(r'\s+', ' ', str(value or '')).strip().lower()

def _normalize_url(url: Optional[str]) -> str:
    return _normalize_text(url).rstrip('/')

def _normalize_severity(severity: Optional[str]) -> str:
    normalized = _normalize_text(severity)
    return {'informational': 'info'}.get(normalized, normalized)

def _normalize_evidence(finding: Dict) -> str:
    evidence = finding.get('evidence', '')
    if isinstance(evidence, (dict, list)):
        evidence = json.dumps(evidence, sort_keys=True, ensure_ascii=False)
    return _normalize_text(evidence)

def _finding_title(finding: Dict) -> str:
    return str(finding.get('title') or finding.get('type') or '')

def _finding_fingerprint(finding: Dict) -> tuple:
    return (
        _normalize_text(_finding_title(finding)),
        _normalize_severity(finding.get('severity', '')),
        _normalize_url(finding.get('url', '')),
        _normalize_evidence(finding)
    )

def _is_expected_ssh_not_found(finding: Dict) -> bool:
    title = _normalize_text(_finding_title(finding))
    description = _normalize_text(finding.get('description', ''))
    return 'expected service not found' in title and 'expected ssh service not found' in description

def _assign_confidence(finding: Dict) -> str:
    existing = _normalize_text(finding.get('confidence_score', ''))
    if existing in {'high', 'medium', 'low'}:
        return existing

    title = _normalize_text(_finding_title(finding))
    description = _normalize_text(finding.get('description', ''))

    if 'missing security headers' in title:
        return 'high'
    if 'information disclosure' in title or 'version disclosure' in title:
        return 'medium'
    if 'csrf protection' in title or 'session management' in title:
        return 'low'
    if 'csrf' in description or 'session' in description:
        return 'low'
    return 'medium'

def _prepare_findings(findings: List[Dict]) -> List[Dict]:
    prepared = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        finding_copy = dict(finding)
        if _is_expected_ssh_not_found(finding_copy):
            finding_copy['severity'] = 'Info'
        finding_copy['confidence_score'] = _assign_confidence(finding_copy)
        key = _finding_fingerprint(finding_copy)
        if key not in prepared:
            prepared[key] = finding_copy
    return list(prepared.values())

def _summarize_confidence(findings: List[Dict]) -> str:
    if not findings:
        return 'N/A'
    score_map = {'high': 3.0, 'medium': 2.0, 'low': 1.0}
    scores = [score_map.get(_normalize_text(f.get('confidence_score', 'medium')), 2.0) for f in findings]
    average = sum(scores) / len(scores)
    if average >= 2.5:
        return 'high'
    if average >= 1.5:
        return 'medium'
    return 'low'
