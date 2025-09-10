

import ast
import json
import re
import hashlib
import subprocess
import tempfile
import os
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
import requests
from pathlib import Path


class VulnerabilityType(Enum):
    """Enhanced vulnerability categorization based on OWASP and CWE"""
    #
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    CRYPTOGRAPHIC_FAILURES = "cryptographic_failures"
    INJECTION = "injection"
    INSECURE_DESIGN = "insecure_design"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    IDENTIFICATION_AUTH_FAILURES = "identification_auth_failures"
    SOFTWARE_DATA_INTEGRITY = "software_data_integrity"
    LOGGING_MONITORING_FAILURES = "logging_monitoring_failures"
    SSRF = "server_side_request_forgery"
    
    # Additional Categories
    HARDCODED_SECRETS = "hardcoded_secrets"
    INSECURE_COMMUNICATION = "insecure_communication"
    WEAK_CRYPTOGRAPHY = "weak_cryptography"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    SUPPLY_CHAIN = "supply_chain"
    INFRASTRUCTURE = "infrastructure"


class SeverityLevel(Enum):
    """CVSS-aligned severity levels"""
    NONE = 0.0
    LOW = 3.9
    MEDIUM = 6.9
    HIGH = 8.9
    CRITICAL = 10.0


@dataclass
class AdvancedVulnerability:
    """Enhanced vulnerability data structure"""
    id: str
    vulnerability_type: VulnerabilityType
    severity: SeverityLevel
    cvss_score: float
    cwe_id: Optional[str]
    title: str
    description: str
    location: Dict[str, Any]  # file, line, column, function, etc.
    code_snippet: Optional[str]
    impact: str
    mitigation: List[str]
    references: List[str]
    confidence: float
    false_positive_likelihood: float
    exploitability: str
    detection_method: str
    metadata: Dict[str, Any]


class ASTSecurityAnalyzer:
    """AST-based static analysis for deep code understanding"""
    
    def __init__(self):
        self.vulnerabilities = []
        self.current_file = ""
        self.function_calls = set()
        self.imported_modules = set()
        
    def analyze_python_code(self, code: str, filename: str = "<string>") -> List[AdvancedVulnerability]:
        """Perform AST-based analysis on Python code"""
        self.current_file = filename
        self.vulnerabilities = []
        
        try:
            tree = ast.parse(code, filename=filename)
            self.visit_ast(tree)
        except SyntaxError as e:
            # Handle syntax errors gracefully
            self.vulnerabilities.append(
                AdvancedVulnerability(
                    id=f"SYNTAX_ERROR_{hash(str(e)) % 10000}",
                    vulnerability_type=VulnerabilityType.INSECURE_DESIGN,
                    severity=SeverityLevel.LOW,
                    cvss_score=2.0,
                    cwe_id="CWE-1164",
                    title="Syntax Error in Code",
                    description=f"Syntax error prevents proper security analysis: {str(e)}",
                    location={"file": filename, "line": e.lineno, "column": e.offset},
                    code_snippet=None,
                    impact="Code cannot be executed, potential deployment issues",
                    mitigation=["Fix syntax errors", "Use proper code linting"],
                    references=["https://docs.python.org/3/tutorial/errors.html"],
                    confidence=1.0,
                    false_positive_likelihood=0.0,
                    exploitability="N/A",
                    detection_method="AST_PARSING",
                    metadata={"error_type": "syntax", "error_msg": str(e)}
                )
            )
        
        return self.vulnerabilities
    
    def visit_ast(self, node: ast.AST):
        """Recursively visit AST nodes for security analysis"""
        for child in ast.walk(node):
            # Check for dangerous function calls
            if isinstance(child, ast.Call):
                self._analyze_function_call(child)
            
            # Check for hardcoded secrets
            elif isinstance(child, ast.Assign):
                self._analyze_assignment(child)
            
            # Check for dangerous imports
            elif isinstance(child, (ast.Import, ast.ImportFrom)):
                self._analyze_import(child)
            
            # Check for SQL injection patterns
            elif isinstance(child, ast.JoinedStr):
                self._analyze_f_string(child)
    
    def _analyze_function_call(self, node: ast.Call):
        """Analyze function calls for security issues"""
        func_name = self._get_function_name(node.func)
        if not func_name:
            return
        
        # Dangerous function calls
        dangerous_functions = {
            'eval': (VulnerabilityType.INJECTION, "CWE-95", "Code Injection via eval()"),
            'exec': (VulnerabilityType.INJECTION, "CWE-95", "Code Injection via exec()"),
            'compile': (VulnerabilityType.INJECTION, "CWE-95", "Code Injection via compile()"),
            'subprocess.call': (VulnerabilityType.INJECTION, "CWE-78", "Command Injection"),
            'subprocess.run': (VulnerabilityType.INJECTION, "CWE-78", "Command Injection"),
            'os.system': (VulnerabilityType.INJECTION, "CWE-78", "Command Injection"),
            'os.popen': (VulnerabilityType.INJECTION, "CWE-78", "Command Injection"),
            'pickle.loads': (VulnerabilityType.SOFTWARE_DATA_INTEGRITY, "CWE-502", "Deserialization Attack"),
            'yaml.load': (VulnerabilityType.SOFTWARE_DATA_INTEGRITY, "CWE-502", "Unsafe YAML Deserialization"),
        }
        
        if func_name in dangerous_functions:
            vuln_type, cwe_id, title = dangerous_functions[func_name]
            
            # Analyze arguments for additional context
            args_analysis = self._analyze_call_arguments(node.args)
            
            vulnerability = AdvancedVulnerability(
                id=f"AST_{func_name.replace('.', '_').upper()}_{node.lineno}",
                vulnerability_type=vuln_type,
                severity=SeverityLevel.HIGH if 'injection' in title.lower() else SeverityLevel.MEDIUM,
                cvss_score=8.5 if 'injection' in title.lower() else 6.5,
                cwe_id=cwe_id,
                title=f"Dangerous Function Call: {title}",
                description=f"Use of {func_name}() can lead to security vulnerabilities",
                location={
                    "file": self.current_file,
                    "line": node.lineno,
                    "column": node.col_offset,
                    "function": func_name
                },
                code_snippet=self._extract_code_snippet(node),
                impact=f"Potential {title.lower()} vulnerability",
                mitigation=[
                    f"Avoid using {func_name}()",
                    "Use safer alternatives",
                    "Validate and sanitize all inputs",
                    "Implement proper input validation"
                ],
                references=[
                    f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html",
                    "https://owasp.org/www-project-top-ten/"
                ],
                confidence=0.9,
                false_positive_likelihood=0.1,
                exploitability="HIGH" if 'injection' in title.lower() else "MEDIUM",
                detection_method="AST_STATIC_ANALYSIS",
                metadata={
                    "function_name": func_name,
                    "arguments": args_analysis,
                    "ast_node_type": type(node).__name__
                }
            )
            
            self.vulnerabilities.append(vulnerability)
    
    def _analyze_assignment(self, node: ast.Assign):
        """Analyze variable assignments for hardcoded secrets"""
        if not node.value or not isinstance(node.value, ast.Constant):
            return
        
        value = str(node.value.value)
        
        # Get variable names
        var_names = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_names.append(target.id.lower())
        
        # Check for hardcoded secrets patterns
        secret_patterns = {
            'password': r'(?i)(password|pwd|pass)',
            'api_key': r'(?i)(api_key|apikey|api-key)',
            'secret': r'(?i)(secret|token|key)',
            'private_key': r'(?i)(private_key|privatekey|private-key)',
            'aws_key': r'(?i)(aws_access_key|aws_secret)',
            'database': r'(?i)(db_password|database_password|conn_string)'
        }
        
        for pattern_name, pattern in secret_patterns.items():
            for var_name in var_names:
                if re.search(pattern, var_name) and len(value) > 8:
                    # Additional checks to reduce false positives
                    if not self._is_likely_placeholder(value):
                        vulnerability = AdvancedVulnerability(
                            id=f"AST_HARDCODED_{pattern_name.upper()}_{node.lineno}",
                            vulnerability_type=VulnerabilityType.HARDCODED_SECRETS,
                            severity=SeverityLevel.HIGH,
                            cvss_score=7.5,
                            cwe_id="CWE-798",
                            title=f"Hardcoded {pattern_name.replace('_', ' ').title()}",
                            description=f"Hardcoded credential found in variable '{var_name}'",
                            location={
                                "file": self.current_file,
                                "line": node.lineno,
                                "column": node.col_offset,
                                "variable": var_name
                            },
                            code_snippet=self._extract_code_snippet(node),
                            impact="Credentials exposed in source code, version control",
                            mitigation=[
                                "Use environment variables for secrets",
                                "Implement secure credential management",
                                "Use configuration files outside version control",
                                "Implement secrets scanning in CI/CD"
                            ],
                            references=[
                                "https://cwe.mitre.org/data/definitions/798.html",
                                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"
                            ],
                            confidence=0.8,
                            false_positive_likelihood=0.2,
                            exploitability="MEDIUM",
                            detection_method="AST_STATIC_ANALYSIS",
                            metadata={
                                "variable_name": var_name,
                                "value_length": len(value),
                                "pattern_matched": pattern_name
                            }
                        )
                        
                        self.vulnerabilities.append(vulnerability)
    
    def _analyze_import(self, node):
        """Analyze imports for dangerous modules"""
        dangerous_modules = {
            'pickle': (VulnerabilityType.SOFTWARE_DATA_INTEGRITY, "CWE-502", "Unsafe Deserialization"),
            'subprocess': (VulnerabilityType.INJECTION, "CWE-78", "Command Injection Risk"),
            'os': (VulnerabilityType.INJECTION, "CWE-78", "System Command Risk"),
            'eval': (VulnerabilityType.INJECTION, "CWE-95", "Code Injection Risk"),
        }
        
        module_names = []
        if isinstance(node, ast.Import):
            module_names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                module_names = [node.module]
        
        for module_name in module_names:
            if module_name in dangerous_modules:
                vuln_type, cwe_id, title = dangerous_modules[module_name]
                
                vulnerability = AdvancedVulnerability(
                    id=f"AST_IMPORT_{module_name.upper()}_{node.lineno}",
                    vulnerability_type=vuln_type,
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.0,
                    cwe_id=cwe_id,
                    title=f"Potentially Dangerous Import: {title}",
                    description=f"Import of {module_name} module requires careful security review",
                    location={
                        "file": self.current_file,
                        "line": node.lineno,
                        "column": node.col_offset,
                        "module": module_name
                    },
                    code_snippet=self._extract_code_snippet(node),
                    impact=f"Potential security risk from {module_name} usage",
                    mitigation=[
                        f"Review all uses of {module_name} module",
                        "Implement proper input validation",
                        "Consider safer alternatives",
                        "Add security controls around dangerous functions"
                    ],
                    references=[
                        f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html"
                    ],
                    confidence=0.6,
                    false_positive_likelihood=0.4,
                    exploitability="MEDIUM",
                    detection_method="AST_STATIC_ANALYSIS",
                    metadata={
                        "module_name": module_name,
                        "import_type": type(node).__name__
                    }
                )
                
                self.vulnerabilities.append(vulnerability)
    
    def _analyze_f_string(self, node: ast.JoinedStr):
        """Analyze f-strings for potential SQL injection"""
        # This is a simplified check - in practice, you'd want more sophisticated analysis
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                vulnerability = AdvancedVulnerability(
                    id=f"AST_SQL_INJECTION_RISK_{node.lineno}",
                    vulnerability_type=VulnerabilityType.INJECTION,
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=6.0,
                    cwe_id="CWE-89",
                    title="Potential SQL Injection via F-String",
                    description="F-string with variable interpolation may be vulnerable to SQL injection",
                    location={
                        "file": self.current_file,
                        "line": node.lineno,
                        "column": node.col_offset
                    },
                    code_snippet=self._extract_code_snippet(node),
                    impact="Potential SQL injection vulnerability",
                    mitigation=[
                        "Use parameterized queries",
                        "Implement input validation and sanitization",
                        "Use ORM query builders",
                        "Avoid string concatenation for SQL queries"
                    ],
                    references=[
                        "https://cwe.mitre.org/data/definitions/89.html",
                        "https://owasp.org/www-community/attacks/SQL_Injection"
                    ],
                    confidence=0.5,
                    false_positive_likelihood=0.6,
                    exploitability="HIGH",
                    detection_method="AST_STATIC_ANALYSIS",
                    metadata={
                        "string_type": "f-string",
                        "has_variables": True
                    }
                )
                
                self.vulnerabilities.append(vulnerability)
                break
    
    def _get_function_name(self, node) -> Optional[str]:
        """Extract function name from AST node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return f"{node.value.id}.{node.attr}"
            elif isinstance(node.value, ast.Attribute):
                parent = self._get_function_name(node.value)
                return f"{parent}.{node.attr}" if parent else None
        return None
    
    def _analyze_call_arguments(self, args) -> Dict[str, Any]:
        """Analyze function call arguments"""
        analysis = {
            "arg_count": len(args),
            "has_user_input": False,
            "has_variables": False,
            "has_constants": False
        }
        
        for arg in args:
            if isinstance(arg, ast.Name):
                analysis["has_variables"] = True
            elif isinstance(arg, ast.Constant):
                analysis["has_constants"] = True
        
        return analysis
    
    def _extract_code_snippet(self, node) -> str:
        """Extract code snippet around the vulnerable line"""
        # This is a simplified implementation
        # In practice, you'd want to maintain the original source code
        return f"Line {node.lineno}: [AST node analysis]"
    
    def _is_likely_placeholder(self, value: str) -> bool:
        """Check if a value is likely a placeholder rather than a real secret"""
        placeholders = [
            'your_key_here', 'placeholder', 'example', 'test', 'demo',
            'changeme', 'replace_me', 'todo', 'fixme', 'xxx', '***'
        ]
        
        value_lower = value.lower()
        return any(placeholder in value_lower for placeholder in placeholders)


class SemanticSecurityAnalyzer:
    """Semantic analysis for context-aware vulnerability detection"""
    
    def __init__(self):
        self.security_contexts = {}
        self.data_flow = {}
        
    def analyze_semantic_patterns(self, code: str, filename: str = "<string>") -> List[AdvancedVulnerability]:
        """Perform semantic analysis to understand security context"""
        vulnerabilities = []
        
        # Analyze authentication patterns
        auth_vulns = self._analyze_authentication_patterns(code, filename)
        vulnerabilities.extend(auth_vulns)
        
        # Analyze authorization patterns
        authz_vulns = self._analyze_authorization_patterns(code, filename)
        vulnerabilities.extend(authz_vulns)
        
        # Analyze cryptographic patterns
        crypto_vulns = self._analyze_cryptographic_patterns(code, filename)
        vulnerabilities.extend(crypto_vulns)
        
        return vulnerabilities
    
    def _analyze_authentication_patterns(self, code: str, filename: str) -> List[AdvancedVulnerability]:
        """Analyze authentication implementation patterns"""
        vulnerabilities = []
        
        # Check for weak authentication patterns
        weak_patterns = [
            (r'(?i)password\s*==\s*["\'][^"\']*["\']', "Hardcoded Password Comparison"),
            (r'(?i)if\s+username\s*==\s*["\'][^"\']*["\']', "Hardcoded Username Check"),
            (r'(?i)auth\s*=\s*False', "Authentication Bypass"),
            (r'(?i)login\(\)\s*:\s*return\s+True', "Always Successful Login"),
        ]
        
        for pattern, description in weak_patterns:
            matches = list(re.finditer(pattern, code, re.MULTILINE))
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                
                vulnerability = AdvancedVulnerability(
                    id=f"SEM_AUTH_{hashlib.md5(description.encode()).hexdigest()[:8]}_{line_num}",
                    vulnerability_type=VulnerabilityType.IDENTIFICATION_AUTH_FAILURES,
                    severity=SeverityLevel.HIGH,
                    cvss_score=8.0,
                    cwe_id="CWE-287",
                    title=f"Authentication Vulnerability: {description}",
                    description=f"Weak authentication pattern detected: {description}",
                    location={
                        "file": filename,
                        "line": line_num,
                        "column": match.start() - code.rfind('\n', 0, match.start())
                    },
                    code_snippet=match.group(0),
                    impact="Authentication bypass, unauthorized access",
                    mitigation=[
                        "Implement proper authentication mechanisms",
                        "Use secure password hashing (bcrypt, Argon2)",
                        "Implement multi-factor authentication",
                        "Use established authentication frameworks"
                    ],
                    references=[
                        "https://cwe.mitre.org/data/definitions/287.html",
                        "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"
                    ],
                    confidence=0.8,
                    false_positive_likelihood=0.2,
                    exploitability="HIGH",
                    detection_method="SEMANTIC_PATTERN_ANALYSIS",
                    metadata={"pattern": pattern, "matched_text": match.group(0)}
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _analyze_authorization_patterns(self, code: str, filename: str) -> List[AdvancedVulnerability]:
        """Analyze authorization and access control patterns"""
        vulnerabilities = []
        
        # Check for authorization bypass patterns
        bypass_patterns = [
            (r'(?i)if\s+user\.is_admin\s*:\s*#\s*bypass', "Admin Bypass Comment"),
            (r'(?i)role\s*=\s*["\']admin["\']', "Hardcoded Admin Role"),
            (r'(?i)permissions\s*=\s*\[\s*\]', "Empty Permissions Array"),
            (r'(?i)access_denied\s*=\s*False', "Access Control Disabled"),
        ]
        
        for pattern, description in bypass_patterns:
            matches = list(re.finditer(pattern, code, re.MULTILINE))
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                
                vulnerability = AdvancedVulnerability(
                    id=f"SEM_AUTHZ_{hashlib.md5(description.encode()).hexdigest()[:8]}_{line_num}",
                    vulnerability_type=VulnerabilityType.BROKEN_ACCESS_CONTROL,
                    severity=SeverityLevel.HIGH,
                    cvss_score=7.5,
                    cwe_id="CWE-285",
                    title=f"Authorization Vulnerability: {description}",
                    description=f"Access control weakness detected: {description}",
                    location={
                        "file": filename,
                        "line": line_num,
                        "column": match.start() - code.rfind('\n', 0, match.start())
                    },
                    code_snippet=match.group(0),
                    impact="Privilege escalation, unauthorized access to resources",
                    mitigation=[
                        "Implement proper access controls",
                        "Use role-based access control (RBAC)",
                        "Implement principle of least privilege",
                        "Regularly audit access controls"
                    ],
                    references=[
                        "https://cwe.mitre.org/data/definitions/285.html",
                        "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"
                    ],
                    confidence=0.7,
                    false_positive_likelihood=0.3,
                    exploitability="HIGH",
                    detection_method="SEMANTIC_PATTERN_ANALYSIS",
                    metadata={"pattern": pattern, "matched_text": match.group(0)}
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _analyze_cryptographic_patterns(self, code: str, filename: str) -> List[AdvancedVulnerability]:
        """Analyze cryptographic implementation patterns"""
        vulnerabilities = []
        
        # Check for weak cryptographic patterns
        crypto_patterns = [
            (r'(?i)hashlib\.md5\(', "Weak Hash Algorithm (MD5)"),
            (r'(?i)hashlib\.sha1\(', "Weak Hash Algorithm (SHA1)"),
            (r'(?i)DES\.new\(', "Weak Encryption Algorithm (DES)"),
            (r'(?i)random\.random\(\)', "Weak Random Number Generation"),
            (r'(?i)ssl_verify\s*=\s*False', "SSL Verification Disabled"),
            (r'(?i)verify\s*=\s*False', "Certificate Verification Disabled"),
        ]
        
        for pattern, description in crypto_patterns:
            matches = list(re.finditer(pattern, code, re.MULTILINE))
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                
                severity = SeverityLevel.HIGH if "weak" in description.lower() else SeverityLevel.MEDIUM
                cvss_score = 7.0 if severity == SeverityLevel.HIGH else 5.0
                
                vulnerability = AdvancedVulnerability(
                    id=f"SEM_CRYPTO_{hashlib.md5(description.encode()).hexdigest()[:8]}_{line_num}",
                    vulnerability_type=VulnerabilityType.CRYPTOGRAPHIC_FAILURES,
                    severity=severity,
                    cvss_score=cvss_score,
                    cwe_id="CWE-327",
                    title=f"Cryptographic Vulnerability: {description}",
                    description=f"Weak cryptographic practice detected: {description}",
                    location={
                        "file": filename,
                        "line": line_num,
                        "column": match.start() - code.rfind('\n', 0, match.start())
                    },
                    code_snippet=match.group(0),
                    impact="Data compromise, authentication bypass, man-in-the-middle attacks",
                    mitigation=[
                        "Use strong cryptographic algorithms (AES, SHA-256+)",
                        "Use cryptographically secure random number generators",
                        "Always verify SSL/TLS certificates",
                        "Keep cryptographic libraries updated"
                    ],
                    references=[
                        "https://cwe.mitre.org/data/definitions/327.html",
                        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
                    ],
                    confidence=0.9,
                    false_positive_likelihood=0.1,
                    exploitability="MEDIUM",
                    detection_method="SEMANTIC_PATTERN_ANALYSIS",
                    metadata={"pattern": pattern, "matched_text": match.group(0)}
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities


class AdvancedSecurityEngine:
    """Main advanced security analysis engine orchestrator"""
    
    def __init__(self):
        self.ast_analyzer = ASTSecurityAnalyzer()
        self.semantic_analyzer = SemanticSecurityAnalyzer()
        self.vulnerability_count = 0
        
    def analyze_code(self, code: str, filename: str = "<string>", language: str = "python") -> Dict[str, Any]:
        """Perform comprehensive multi-layer security analysis"""
        start_time = datetime.now()
        all_vulnerabilities = []
        
        # Layer 1: AST-based static analysis
        if language.lower() == "python":
            ast_vulnerabilities = self.ast_analyzer.analyze_python_code(code, filename)
            all_vulnerabilities.extend(ast_vulnerabilities)
        
        # Layer 2: Semantic analysis
        semantic_vulnerabilities = self.semantic_analyzer.analyze_semantic_patterns(code, filename)
        all_vulnerabilities.extend(semantic_vulnerabilities)
        
        # Layer 3: Pattern-based analysis (legacy compatibility)
        pattern_vulnerabilities = self._legacy_pattern_analysis(code, filename)
        all_vulnerabilities.extend(pattern_vulnerabilities)
        
        # Sort by severity and confidence
        all_vulnerabilities.sort(key=lambda v: (-v.severity.value, -v.confidence))
        
        # Generate risk summary
        risk_summary = self._generate_risk_summary(all_vulnerabilities)
        
        analysis_time = (datetime.now() - start_time).total_seconds()
        
        return {
            "analysis_id": f"ADV_{int(datetime.now().timestamp())}",
            "timestamp": datetime.now().isoformat(),
            "filename": filename,
            "language": language,
            "analysis_time": analysis_time,
            "detection_layers": ["AST_STATIC_ANALYSIS", "SEMANTIC_ANALYSIS", "PATTERN_MATCHING"],
            "vulnerability_count": len(all_vulnerabilities),
            "summary": risk_summary,
            "vulnerabilities": [asdict(vuln) for vuln in all_vulnerabilities],
            "risk_score": self._calculate_risk_score(all_vulnerabilities),
            "compliance_status": self._assess_compliance(all_vulnerabilities),
            "recommendations": self._generate_recommendations(all_vulnerabilities)
        }
    
    def _legacy_pattern_analysis(self, code: str, filename: str) -> List[AdvancedVulnerability]:
        """Legacy pattern-based analysis for backward compatibility"""
        vulnerabilities = []
        
        # Enhanced regex patterns with better categorization
        enhanced_patterns = [
            {
                'pattern': r'(?i)password\s*=\s*["\'][^"\']{8,}["\']',
                'vuln_type': VulnerabilityType.HARDCODED_SECRETS,
                'title': 'Hardcoded Password',
                'cwe': 'CWE-798',
                'severity': SeverityLevel.HIGH
            },
            {
                'pattern': r'(?i)(SELECT|INSERT|UPDATE|DELETE).*\+.*',
                'vuln_type': VulnerabilityType.INJECTION,
                'title': 'Potential SQL Injection',
                'cwe': 'CWE-89',
                'severity': SeverityLevel.HIGH
            },
            {
                'pattern': r'(?i)requests\.get\([^)]*verify\s*=\s*False',
                'vuln_type': VulnerabilityType.INSECURE_COMMUNICATION,
                'title': 'SSL Verification Disabled',
                'cwe': 'CWE-295',
                'severity': SeverityLevel.MEDIUM
            }
        ]
        
        for pattern_config in enhanced_patterns:
            matches = list(re.finditer(pattern_config['pattern'], code, re.MULTILINE))
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                
                vulnerability = AdvancedVulnerability(
                    id=f"PAT_{pattern_config['cwe'].replace('-', '_')}_{line_num}",
                    vulnerability_type=pattern_config['vuln_type'],
                    severity=pattern_config['severity'],
                    cvss_score=pattern_config['severity'].value,
                    cwe_id=pattern_config['cwe'],
                    title=pattern_config['title'],
                    description=f"Pattern-based detection: {pattern_config['title']}",
                    location={
                        "file": filename,
                        "line": line_num,
                        "column": match.start() - code.rfind('\n', 0, match.start())
                    },
                    code_snippet=match.group(0),
                    impact="Security vulnerability detected by pattern matching",
                    mitigation=["Review and remediate the identified code pattern"],
                    references=[f"https://cwe.mitre.org/data/definitions/{pattern_config['cwe'].split('-')[1]}.html"],
                    confidence=0.7,
                    false_positive_likelihood=0.3,
                    exploitability="MEDIUM",
                    detection_method="PATTERN_MATCHING",
                    metadata={"pattern": pattern_config['pattern'], "matched_text": match.group(0)}
                )
                
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _generate_risk_summary(self, vulnerabilities: List[AdvancedVulnerability]) -> Dict[str, Any]:
        """Generate comprehensive risk summary"""
        if not vulnerabilities:
            return {
                "total_issues": 0,
                "risk_level": "LOW",
                "severity_breakdown": {},
                "top_categories": [],
                "critical_issues": 0
            }
        
        severity_counts = {}
        category_counts = {}
        
        for vuln in vulnerabilities:
            # Count by severity
            severity = vuln.severity.name
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by category
            category = vuln.vulnerability_type.value
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Determine overall risk level
        critical_count = severity_counts.get('CRITICAL', 0)
        high_count = severity_counts.get('HIGH', 0)
        
        if critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count > 2:
            risk_level = "HIGH"
        elif high_count > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # Top categories
        top_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            "total_issues": len(vulnerabilities),
            "risk_level": risk_level,
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts,
            "top_categories": [{"category": cat, "count": count} for cat, count in top_categories],
            "critical_issues": critical_count,
            "high_issues": high_count
        }
    
    def _calculate_risk_score(self, vulnerabilities: List[AdvancedVulnerability]) -> float:
        """Calculate overall risk score (0-100)"""
        if not vulnerabilities:
            return 0.0
        
        total_score = 0.0
        for vuln in vulnerabilities:
            # Weight by severity and confidence
            weighted_score = vuln.cvss_score * vuln.confidence
            total_score += weighted_score
        
        # Normalize to 0-100 scale
        max_possible_score = len(vulnerabilities) * 10.0
        normalized_score = min(100.0, (total_score / max_possible_score) * 100.0)
        
        return round(normalized_score, 2)
    
    def _assess_compliance(self, vulnerabilities: List[AdvancedVulnerability]) -> Dict[str, Any]:
        """Assess compliance with security standards"""
        compliance_issues = {
            "OWASP_TOP_10": [],
            "CWE_TOP_25": [],
            "PCI_DSS": [],
            "SOC2": []
        }
        
        for vuln in vulnerabilities:
            # Map to OWASP Top 10
            owasp_mapping = {
                VulnerabilityType.BROKEN_ACCESS_CONTROL: "A01:2021-Broken Access Control",
                VulnerabilityType.CRYPTOGRAPHIC_FAILURES: "A02:2021-Cryptographic Failures",
                VulnerabilityType.INJECTION: "A03:2021-Injection",
                VulnerabilityType.INSECURE_DESIGN: "A04:2021-Insecure Design",
                VulnerabilityType.SECURITY_MISCONFIGURATION: "A05:2021-Security Misconfiguration"
            }
            
            if vuln.vulnerability_type in owasp_mapping:
                compliance_issues["OWASP_TOP_10"].append({
                    "category": owasp_mapping[vuln.vulnerability_type],
                    "vulnerability_id": vuln.id,
                    "severity": vuln.severity.name
                })
        
        return compliance_issues
    
    def _generate_recommendations(self, vulnerabilities: List[AdvancedVulnerability]) -> List[str]:
        """Generate prioritized recommendations"""
        if not vulnerabilities:
            return ["No security issues detected. Continue following secure coding practices."]
        
        recommendations = []
        
        # Critical issues first
        critical_vulns = [v for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL]
        if critical_vulns:
            recommendations.append("URGENT: Address critical security vulnerabilities immediately")
        
        # High severity issues
        high_vulns = [v for v in vulnerabilities if v.severity == SeverityLevel.HIGH]
        if high_vulns:
            recommendations.append(f"High Priority: Remediate {len(high_vulns)} high-severity vulnerabilities")
        
        # Category-specific recommendations
        categories = set(v.vulnerability_type for v in vulnerabilities)
        
        if VulnerabilityType.HARDCODED_SECRETS in categories:
            recommendations.append("Implement secure credential management system")
        
        if VulnerabilityType.INJECTION in categories:
            recommendations.append("Implement input validation and parameterized queries")
        
        if VulnerabilityType.CRYPTOGRAPHIC_FAILURES in categories:
            recommendations.append("Update cryptographic implementations to use strong algorithms")
        
        # General recommendations
        recommendations.extend([
            "Integrate security scanning into CI/CD pipeline",
            "Conduct regular security code reviews",
            "Implement security training for development team",
            "Establish security testing procedures"
        ])
        
        return recommendations[:8]  # Limit to top 8 recommendations


# Integration with existing AuditMind class
def create_advanced_audit_mind():
    """Factory function to create AuditMind with advanced capabilities"""
    return AdvancedSecurityEngine()


if __name__ == "__main__":
    # Test the advanced security engine
    engine = AdvancedSecurityEngine()
    
    test_code = '''
import subprocess
import hashlib

password = "hardcoded_secret_123"
api_key = "sk-1234567890abcdef"

def login(username, password):
    if username == "admin":
        return True
    
    query = f"SELECT * FROM users WHERE name='{username}'"
    
def unsafe_function(user_input):
    eval(user_input)
    result = subprocess.call(user_input, shell=True)
    return result

def weak_crypto(data):
    return hashlib.md5(data.encode()).hexdigest()
'''
    
    result = engine.analyze_code(test_code, "test_file.py")
    print(json.dumps(result, indent=2, default=str))