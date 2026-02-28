import os
import re
from typing import Dict, List, Tuple
import hashlib

class FileThreatAnalyzer:
    """Analyze files for security threats and malicious content"""
    
    # Suspicious file extensions
    DANGEROUS_EXTENSIONS = [
        '.exe', '.dll', '.bat', '.cmd', '.sh', '.php', 
        '.jsp', '.asp', '.aspx', '.jar', '.war', '.ear',
        '.py', '.rb', '.pl', '.cgi', '.com', '.scr',
        '.vbs', '.js', '.wsf', '.hta', '.msi', '.msp'
    ]
    
    # Suspicious patterns in file content
    MALICIOUS_PATTERNS = {
        'shellcode': [
            rb'\\x[0-9a-fA-F]{2}',  # Hex encoded shellcode
            rb'\\u[0-9a-fA-F]{4}',  # Unicode escape sequences
        ],
        'scripts': [
            rb'<script[^>]*>.*?</script>',  # JavaScript tags
            rb'eval\s*\(',  # eval() function
            rb'document\.write',  # document.write
            rb'window\.location',  # redirects
        ],
        'sql_injection': [
            rb'union\s+select',  # SQL injection
            rb'insert\s+into',  # SQL insert
            rb'delete\s+from',  # SQL delete
            rb'drop\s+table',  # SQL drop
            rb'or\s+1\s*=\s*1',  # SQL boolean
        ],
        'command_injection': [
            rb'exec\s*\(',  # exec function
            rb'system\s*\(',  # system function
            rb'subprocess\.call',  # subprocess calls
            rb'os\.system',  # os.system calls
        ],
        'malware_signatures': [
            rb'Trojan',  # Trojan signatures
            rb'Backdoor',
            rb'Keylogger',
            rb'Rootkit',
            rb'\\x90\\x90\\x90\\x90',  # NOP sled
        ]
    }
    
    # Suspicious keywords
    SUSPICIOUS_KEYWORDS = [
        'password', 'passwd', 'pwd', 'credential', 'secret',
        'hack', 'exploit', 'payload', 'shell', 'reverse',
        'backdoor', 'trojan', 'malware', 'virus', 'worm',
        'encrypt', 'decrypt', 'ransomware', 'bitcoin', 'wallet'
    ]
    
    def __init__(self):
        self.max_file_size = 50 * 1024 * 1024  # 50MB limit
        
    def analyze_file(self, file_path: str, original_filename: str) -> Dict:
        """Analyze a single file for threats"""
        
        if not os.path.exists(file_path):
            return {
                'filename': original_filename,
                'status': 'error',
                'error': 'File not found',
                'risk_score': 100,
                'severity': 'High'
            }
        
        # Get file information
        file_size = os.path.getsize(file_path)
        file_extension = os.path.splitext(original_filename)[1].lower()
        
        # Check file size
        if file_size > self.max_file_size:
            return {
                'filename': original_filename,
                'status': 'error',
                'error': 'File too large (max 50MB)',
                'risk_score': 50,
                'severity': 'Medium'
            }
        
        # Calculate risk score
        risk_score = 0
        threat_indicators = []
        
        # Check file extension
        if file_extension in self.DANGEROUS_EXTENSIONS:
            risk_score += 30
            threat_indicators.append(f"Dangerous file extension: {file_extension}")
        
        # Read file content
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # Check for suspicious patterns
            pattern_results = self._check_patterns(content)
            risk_score += pattern_results['score']
            threat_indicators.extend(pattern_results['indicators'])
            
            # Check for suspicious keywords in text content
            try:
                text_content = content.decode('utf-8', errors='ignore')
                keyword_results = self._check_keywords(text_content)
                risk_score += keyword_results['score']
                threat_indicators.extend(keyword_results['indicators'])
                
                # Check for encoded content
                encoding_results = self._check_encoding(text_content)
                risk_score += encoding_results['score']
                threat_indicators.extend(encoding_results['indicators'])
                
            except Exception:
                pass
            
            # Calculate file hash for identification
            file_hash = hashlib.sha256(content).hexdigest()
            
        except Exception as e:
            return {
                'filename': original_filename,
                'status': 'error',
                'error': f"Error reading file: {str(e)}",
                'risk_score': 50,
                'severity': 'Medium'
            }
        
        # Determine severity
        severity = self._determine_severity(risk_score)
        
        # Determine threat type
        threat_type = self._determine_threat_type(threat_indicators, file_extension)
        
        return {
            'filename': original_filename,
            'file_size': file_size,
            'file_extension': file_extension,
            'file_hash': file_hash[:16] + '...' if len(file_hash) > 16 else file_hash,
            'status': 'complete',
            'risk_score': min(risk_score, 100),
            'severity': severity,
            'threat_type': threat_type,
            'threat_indicators': threat_indicators,
            'confidence': 0.75 if risk_score > 50 else 0.85
        }
    
    def analyze_multiple_files(self, files_data: List[Tuple[str, str]]) -> Dict:
        """Analyze multiple files and return aggregated results"""
        
        results = []
        total_risk = 0
        high_risk_count = 0
        medium_risk_count = 0
        
        for file_path, original_filename in files_data:
            result = self.analyze_file(file_path, original_filename)
            results.append(result)
            
            if result['status'] == 'complete':
                total_risk += result['risk_score']
                if result['severity'] == 'High':
                    high_risk_count += 1
                elif result['severity'] == 'Medium':
                    medium_risk_count += 1
        
        # Calculate overall risk
        completed_files = [r for r in results if r['status'] == 'complete']
        if completed_files:
            avg_risk = total_risk / len(completed_files)
        else:
            avg_risk = 0
        
        # Determine overall severity
        if high_risk_count > 0:
            overall_severity = 'High'
        elif medium_risk_count > 0:
            overall_severity = 'Medium'
        else:
            overall_severity = 'Low'
        
        return {
            'total_files': len(results),
            'analyzed_files': len([r for r in results if r['status'] == 'complete']),
            'error_files': len([r for r in results if r['status'] == 'error']),
            'overall_risk_score': min(int(avg_risk), 100),
            'overall_severity': overall_severity,
            'high_risk_files': high_risk_count,
            'medium_risk_files': medium_risk_count,
            'file_results': results,
            'status': 'complete'
        }
    
    def _check_patterns(self, content: bytes) -> Dict:
        """Check for suspicious patterns in file content"""
        score = 0
        indicators = []
        
        for category, patterns in self.MALICIOUS_PATTERNS.items():
            for pattern in patterns:
                matches = len(re.findall(pattern, content, re.IGNORECASE))
                if matches > 0:
                    score += min(matches * 10, 30)
                    indicators.append(f"Found {category} pattern ({matches} occurrences)")
        
        return {'score': min(score, 50), 'indicators': indicators}
    
    def _check_keywords(self, text_content: str) -> Dict:
        """Check for suspicious keywords"""
        score = 0
        indicators = []
        text_lower = text_content.lower()
        
        for keyword in self.SUSPICIOUS_KEYWORDS:
            count = text_lower.count(keyword)
            if count > 0:
                score += min(count * 5, 20)
                indicators.append(f"Suspicious keyword '{keyword}' found ({count} times)")
        
        return {'score': min(score, 40), 'indicators': indicators}
    
    def _check_encoding(self, text_content: str) -> Dict:
        """Check for suspicious encoding or obfuscation"""
        score = 0
        indicators = []
        
        # Check for base64 encoded content
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        base64_matches = len(re.findall(base64_pattern, text_content))
        if base64_matches > 5:
            score += 15
            indicators.append(f"Possible base64 encoded content ({base64_matches} occurrences)")
        
        # Check for hex encoded content
        hex_pattern = r'\\x[0-9a-fA-F]{2}'
        hex_matches = len(re.findall(hex_pattern, text_content))
        if hex_matches > 10:
            score += 20
            indicators.append(f"Hex encoded content detected ({hex_matches} occurrences)")
        
        # Check for excessive obfuscation
        if text_content.count('\\') > 50:
            score += 10
            indicators.append("High level of escaping/obfuscation detected")
        
        return {'score': min(score, 45), 'indicators': indicators}
    
    def _determine_severity(self, risk_score: int) -> str:
        """Determine severity level based on risk score"""
        if risk_score <= 30:
            return 'Low'
        elif risk_score <= 70:
            return 'Medium'
        else:
            return 'High'
    
    def _determine_threat_type(self, indicators: List[str], extension: str) -> str:
        """Determine the type of threat based on indicators"""
        
        if 'shellcode' in str(indicators).lower():
            return 'Malware Detection'
        elif 'sql' in str(indicators).lower():
            return 'SQL Injection'
        elif 'script' in str(indicators).lower() or extension in ['.js', '.vbs']:
            return 'Malicious Script'
        elif any(ind in str(indicators).lower() for ind in ['password', 'credential', 'secret']):
            return 'Data Exfiltration Risk'
        elif extension in self.DANGEROUS_EXTENSIONS:
            return 'Suspicious File'
        elif len(indicators) > 3:
            return 'Suspicious Content'
        else:
            return 'Normal File'
