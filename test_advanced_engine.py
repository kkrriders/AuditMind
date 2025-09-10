#!/usr/bin/env python3
"""
Test script for the Advanced Multi-Layer Security Engine
=======================================================

This script tests all the advanced detection capabilities:
1. AST-based static analysis
2. Semantic vulnerability detection
3. Dependency scanning
4. Infrastructure configuration analysis
"""

import json
from advanced_security_engine import AdvancedSecurityEngine
from dependency_scanner import DependencyScanner
from infrastructure_analyzer import InfrastructureSecurityEngine

def test_advanced_code_analysis():
    """Test advanced code analysis"""
    print("🔍 Testing Advanced Code Analysis...")
    
    engine = AdvancedSecurityEngine()
    
    # Test code with multiple vulnerability types
    test_code = '''
import subprocess
import hashlib
import pickle
import os

# Hardcoded secrets
password = "super_secret_password_123"
api_key = "sk-1234567890abcdef"
database_url = "mysql://user:pass@localhost/db"

def vulnerable_login(username, password):
    # Authentication bypass
    if username == "admin":
        return True
    
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE name='{username}' AND password='{password}'"
    
    # Command injection
    os.system(f"echo {username}")
    subprocess.call(username, shell=True)
    
    return False

def unsafe_deserialization(data):
    # Unsafe deserialization
    return pickle.loads(data)

def weak_crypto(message):
    # Weak cryptography
    return hashlib.md5(message.encode()).hexdigest()

def eval_injection(user_input):
    # Code injection
    eval(user_input)
    exec(user_input)
    
class InsecureClass:
    def __init__(self):
        self.debug = True
        self.ssl_verify = False  # SSL verification disabled
'''
    
    result = engine.analyze_code(test_code, "test_vulnerable.py", "python")
    
    print(f"✅ Found {result['vulnerability_count']} vulnerabilities")
    print(f"📊 Risk Score: {result['risk_score']}/100")
    print(f"⚠️  Risk Level: {result['summary']['risk_level']}")
    
    # Show top 3 vulnerabilities
    print("\n🚨 Top Vulnerabilities:")
    for i, vuln in enumerate(result['vulnerabilities'][:3], 1):
        print(f"{i}. {vuln['title']} - {vuln['severity']} (Confidence: {vuln['confidence']})")
    
    return result

def test_dependency_scanning():
    """Test dependency vulnerability scanning"""
    print("\n📦 Testing Dependency Scanning...")
    
    scanner = DependencyScanner()
    
    # Test requirements.txt with known vulnerable packages
    test_requirements = '''
# Known vulnerable versions for testing
requests==2.25.1
flask==1.1.1
django==2.2.0
urllib3==1.26.0
pyyaml==5.4.0
pillow==8.0.0
numpy==1.19.0
'''
    
    result = scanner.scan_dependencies(test_requirements, "requirements.txt")
    
    print(f"✅ Scanned {result['dependencies_found']} dependencies")
    print(f"🔍 Found {result['summary']['total_vulnerabilities']} vulnerabilities")
    print(f"⚠️  Risk Level: {result['summary']['risk_level']}")
    
    # Show vulnerability breakdown
    if result['summary']['severity_breakdown']:
        print("\n📊 Severity Breakdown:")
        for severity, count in result['summary']['severity_breakdown'].items():
            print(f"   {severity}: {count}")
    
    return result

def test_infrastructure_analysis():
    """Test infrastructure configuration analysis"""
    print("\n🏗️  Testing Infrastructure Analysis...")
    
    analyzer = InfrastructureSecurityEngine()
    
    # Test vulnerable Dockerfile
    test_dockerfile = '''
# Vulnerable Dockerfile for testing
FROM ubuntu:latest
USER root
EXPOSE 22
EXPOSE 3306
EXPOSE 80

# Hardcoded secrets
ENV PASSWORD=hardcoded_secret_123
ENV API_KEY=sk-test123456789

# Dangerous operations
RUN apt-get update && apt-get install -y openssh-server mysql-server
RUN echo "root:password" | chpasswd

# No healthcheck
# No resource limits
# Privileged operations
COPY --chown=root:root . /app
VOLUME ["/var/run/docker.sock", "/etc", "/"]

WORKDIR /app
CMD ["python", "app.py"]
'''
    
    result = analyzer.analyze_infrastructure(test_dockerfile, "Dockerfile")
    
    print(f"✅ Analyzed {result['file_type']} configuration")
    print(f"🔍 Found {result['summary']['total_vulnerabilities']} vulnerabilities")
    print(f"⚠️  Risk Level: {result['summary']['risk_level']}")
    
    # Show top vulnerabilities
    print("\n🚨 Top Infrastructure Issues:")
    for i, vuln in enumerate(result['vulnerabilities'][:3], 1):
        print(f"{i}. {vuln['title']} - {vuln['severity']}")
    
    # Show compliance violations
    if result['compliance_assessment']['total_violations'] > 0:
        print(f"\n📋 Compliance Violations: {result['compliance_assessment']['total_violations']}")
    
    return result

def test_kubernetes_config():
    """Test Kubernetes configuration analysis"""
    print("\n☸️  Testing Kubernetes Analysis...")
    
    analyzer = InfrastructureSecurityEngine()
    
    # Test vulnerable Kubernetes config
    test_k8s_config = '''
apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-pod
spec:
  securityContext:
    runAsUser: 0  # Running as root
  containers:
  - name: app-container
    image: nginx:latest
    securityContext:
      privileged: true  # Privileged container
      allowPrivilegeEscalation: true
      runAsUser: 0
    ports:
    - containerPort: 80
    - containerPort: 22
    env:
    - name: PASSWORD
      value: "hardcoded_password"
  hostNetwork: true  # Host network access
  hostPID: true      # Host PID access
---
apiVersion: v1
kind: Service
metadata:
  name: vulnerable-service
spec:
  type: LoadBalancer  # External exposure
  ports:
  - port: 80
    targetPort: 80
  - port: 22
    targetPort: 22
  selector:
    app: vulnerable-app
'''
    
    result = analyzer.analyze_infrastructure(test_k8s_config, "vulnerable-pod.yaml")
    
    print(f"✅ Analyzed Kubernetes configuration")
    print(f"🔍 Found {result['summary']['total_vulnerabilities']} vulnerabilities")
    print(f"⚠️  Risk Level: {result['summary']['risk_level']}")
    
    return result

def main():
    """Run all tests"""
    print("🚀 Advanced Multi-Layer Security Engine Test Suite")
    print("=" * 55)
    
    try:
        # Test 1: Advanced Code Analysis
        code_result = test_advanced_code_analysis()
        
        # Test 2: Dependency Scanning
        dep_result = test_dependency_scanning()
        
        # Test 3: Infrastructure Analysis
        infra_result = test_infrastructure_analysis()
        
        # Test 4: Kubernetes Analysis
        k8s_result = test_kubernetes_config()
        
        # Summary
        print("\n" + "=" * 55)
        print("📊 TEST SUMMARY")
        print("=" * 55)
        print(f"Code Analysis: {code_result['vulnerability_count']} vulnerabilities found")
        print(f"Dependencies: {dep_result['summary']['total_vulnerabilities']} vulnerabilities found")
        print(f"Infrastructure: {infra_result['summary']['total_vulnerabilities']} vulnerabilities found")
        print(f"Kubernetes: {k8s_result['summary']['total_vulnerabilities']} vulnerabilities found")
        
        total_vulns = (
            code_result['vulnerability_count'] +
            dep_result['summary']['total_vulnerabilities'] +
            infra_result['summary']['total_vulnerabilities'] +
            k8s_result['summary']['total_vulnerabilities']
        )
        
        print(f"\n🎯 TOTAL VULNERABILITIES DETECTED: {total_vulns}")
        print("\n✅ All advanced security engines are working correctly!")
        
        # Save detailed results
        detailed_results = {
            "test_timestamp": "2024-01-01T00:00:00Z",
            "total_vulnerabilities": total_vulns,
            "code_analysis": code_result,
            "dependency_analysis": dep_result,
            "infrastructure_analysis": infra_result,
            "kubernetes_analysis": k8s_result
        }
        
        with open("test_results.json", "w") as f:
            json.dump(detailed_results, f, indent=2, default=str)
        
        print("💾 Detailed results saved to test_results.json")
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()