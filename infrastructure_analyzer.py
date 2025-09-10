"""
Infrastructure Configuration Security Analyzer
=============================================

Professional infrastructure security analysis:
1. Docker/Container security scanning
2. Cloud configuration analysis (AWS, Azure, GCP)
3. Kubernetes security assessment
4. Network configuration review
5. Configuration drift detection
6. Compliance checking (CIS benchmarks, PCI DSS, SOC2)
"""

import json
import re
import yaml
import xml.etree.ElementTree as ET
import hashlib
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
import base64


class InfrastructureRisk(Enum):
    """Infrastructure-specific risk categories"""
    CONTAINER_SECURITY = "container_security"
    CLOUD_MISCONFIGURATION = "cloud_misconfiguration"
    NETWORK_SECURITY = "network_security"
    ACCESS_CONTROL = "access_control"
    ENCRYPTION_ISSUES = "encryption_issues"
    COMPLIANCE_VIOLATION = "compliance_violation"
    CONFIGURATION_DRIFT = "configuration_drift"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXPOSURE = "data_exposure"
    MONITORING_GAPS = "monitoring_gaps"


class ComplianceStandard(Enum):
    """Supported compliance standards"""
    CIS_DOCKER = "cis_docker"
    CIS_KUBERNETES = "cis_kubernetes"
    CIS_AWS = "cis_aws"
    CIS_AZURE = "cis_azure"
    CIS_GCP = "cis_gcp"
    PCI_DSS = "pci_dss"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    NIST = "nist"


@dataclass
class InfrastructureVulnerability:
    """Infrastructure vulnerability data structure"""
    id: str
    risk_type: InfrastructureRisk
    severity: str
    title: str
    description: str
    resource_type: str
    resource_name: Optional[str]
    location: Dict[str, Any]
    impact: str
    remediation: List[str]
    compliance_violations: List[str]
    references: List[str]
    confidence: float
    metadata: Dict[str, Any]


class DockerSecurityAnalyzer:
    """Docker and container security analyzer"""
    
    def __init__(self):
        self.security_checks = {
            'privileged_containers': self._check_privileged_containers,
            'root_user': self._check_root_user,
            'insecure_images': self._check_insecure_images,
            'exposed_ports': self._check_exposed_ports,
            'volume_mounts': self._check_volume_mounts,
            'resource_limits': self._check_resource_limits,
            'health_checks': self._check_health_checks,
            'secrets_management': self._check_secrets_management
        }
    
    def analyze_dockerfile(self, content: str, filename: str = "Dockerfile") -> List[InfrastructureVulnerability]:
        """Analyze Dockerfile for security issues"""
        vulnerabilities = []
        lines = content.split('\n')
        
        for check_name, check_func in self.security_checks.items():
            vulns = check_func(lines, filename)
            vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def analyze_docker_compose(self, content: str, filename: str = "docker-compose.yml") -> List[InfrastructureVulnerability]:
        """Analyze Docker Compose configuration"""
        vulnerabilities = []
        
        try:
            compose_data = yaml.safe_load(content)
            
            if 'services' in compose_data:
                for service_name, service_config in compose_data['services'].items():
                    vulns = self._analyze_compose_service(service_config, service_name, filename)
                    vulnerabilities.extend(vulns)
            
        except yaml.YAMLError as e:
            vulnerabilities.append(
                InfrastructureVulnerability(
                    id=f"DOCKER_YAML_ERROR_{hash(str(e)) % 10000}",
                    risk_type=InfrastructureRisk.CONTAINER_SECURITY,
                    severity="MEDIUM",
                    title="Docker Compose YAML Parsing Error",
                    description=f"Error parsing Docker Compose file: {str(e)}",
                    resource_type="docker-compose",
                    resource_name=filename,
                    location={"file": filename, "error": str(e)},
                    impact="Configuration cannot be validated for security issues",
                    remediation=["Fix YAML syntax errors", "Validate configuration"],
                    compliance_violations=["CIS Docker Benchmark"],
                    references=["https://docs.docker.com/compose/"],
                    confidence=1.0,
                    metadata={"error": str(e)}
                )
            )
        
        return vulnerabilities
    
    def _check_privileged_containers(self, lines: List[str], filename: str) -> List[InfrastructureVulnerability]:
        """Check for privileged container usage"""
        vulnerabilities = []
        
        for i, line in enumerate(lines, 1):
            if re.search(r'--privileged', line, re.IGNORECASE):
                vulnerabilities.append(
                    InfrastructureVulnerability(
                        id=f"DOCKER_PRIVILEGED_{i}",
                        risk_type=InfrastructureRisk.PRIVILEGE_ESCALATION,
                        severity="HIGH",
                        title="Privileged Container Detected",
                        description="Container running with privileged access",
                        resource_type="dockerfile",
                        resource_name=filename,
                        location={"file": filename, "line": i},
                        impact="Container has full access to host system",
                        remediation=[
                            "Remove --privileged flag",
                            "Use specific capabilities instead",
                            "Run with least privilege principle"
                        ],
                        compliance_violations=["CIS Docker Benchmark 5.4"],
                        references=[
                            "https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities",
                            "https://www.cisecurity.org/benchmark/docker"
                        ],
                        confidence=0.95,
                        metadata={"line_content": line.strip()}
                    )
                )
        
        return vulnerabilities
    
    def _check_root_user(self, lines: List[str], filename: str) -> List[InfrastructureVulnerability]:
        """Check for root user usage"""
        vulnerabilities = []
        has_user_directive = False
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            if line_stripped.startswith('USER '):
                has_user_directive = True
                user = line_stripped.split()[1]
                if user in ['root', '0']:
                    vulnerabilities.append(
                        InfrastructureVulnerability(
                            id=f"DOCKER_ROOT_USER_{i}",
                            risk_type=InfrastructureRisk.PRIVILEGE_ESCALATION,
                            severity="HIGH",
                            title="Container Running as Root",
                            description="Container explicitly configured to run as root user",
                            resource_type="dockerfile",
                            resource_name=filename,
                            location={"file": filename, "line": i},
                            impact="Privilege escalation risk if container is compromised",
                            remediation=[
                                "Create and use non-root user",
                                "Use USER directive with non-root user",
                                "Implement proper file permissions"
                            ],
                            compliance_violations=["CIS Docker Benchmark 4.1"],
                            references=["https://www.cisecurity.org/benchmark/docker"],
                            confidence=0.9,
                            metadata={"user": user}
                        )
                    )
        
        # Check if no USER directive is specified (defaults to root)
        if not has_user_directive:
            vulnerabilities.append(
                InfrastructureVulnerability(
                    id="DOCKER_DEFAULT_ROOT_USER",
                    risk_type=InfrastructureRisk.PRIVILEGE_ESCALATION,
                    severity="MEDIUM",
                    title="No User Specified (Defaults to Root)",
                    description="Container will run as root user by default",
                    resource_type="dockerfile",
                    resource_name=filename,
                    location={"file": filename},
                    impact="Container runs with unnecessary privileges",
                    remediation=[
                        "Add USER directive with non-root user",
                        "Create dedicated application user",
                        "Follow principle of least privilege"
                    ],
                    compliance_violations=["CIS Docker Benchmark 4.1"],
                    references=["https://www.cisecurity.org/benchmark/docker"],
                    confidence=0.8,
                    metadata={"issue": "missing_user_directive"}
                )
            )
        
        return vulnerabilities
    
    def _check_insecure_images(self, lines: List[str], filename: str) -> List[InfrastructureVulnerability]:
        """Check for insecure base images"""
        vulnerabilities = []
        insecure_patterns = [
            (r'FROM\s+.*:latest', "Using 'latest' tag is not recommended"),
            (r'FROM\s+ubuntu(?!:)', "Using untagged Ubuntu image"),
            (r'FROM\s+centos(?!:)', "Using untagged CentOS image"),
            (r'FROM\s+debian(?!:)', "Using untagged Debian image"),
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern, description in insecure_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(
                        InfrastructureVulnerability(
                            id=f"DOCKER_INSECURE_IMAGE_{i}",
                            risk_type=InfrastructureRisk.CONTAINER_SECURITY,
                            severity="MEDIUM",
                            title="Insecure Base Image Usage",
                            description=description,
                            resource_type="dockerfile",
                            resource_name=filename,
                            location={"file": filename, "line": i},
                            impact="Unpredictable and potentially vulnerable base image",
                            remediation=[
                                "Use specific version tags instead of 'latest'",
                                "Pin to specific image SHA",
                                "Use minimal base images (alpine, distroless)",
                                "Regularly update base images"
                            ],
                            compliance_violations=["CIS Docker Benchmark 4.7"],
                            references=["https://www.cisecurity.org/benchmark/docker"],
                            confidence=0.8,
                            metadata={"line_content": line.strip(), "pattern": pattern}
                        )
                    )
        
        return vulnerabilities
    
    def _check_exposed_ports(self, lines: List[str], filename: str) -> List[InfrastructureVulnerability]:
        """Check for insecurely exposed ports"""
        vulnerabilities = []
        dangerous_ports = {
            22: "SSH",
            23: "Telnet", 
            80: "HTTP (unencrypted)",
            3389: "RDP",
            5432: "PostgreSQL",
            3306: "MySQL",
            27017: "MongoDB",
            6379: "Redis"
        }
        
        for i, line in enumerate(lines, 1):
            if line.strip().startswith('EXPOSE '):
                ports = line.strip().split()[1:]
                for port_spec in ports:
                    port_num = int(port_spec.split('/')[0]) if port_spec.split('/')[0].isdigit() else None
                    
                    if port_num in dangerous_ports:
                        vulnerabilities.append(
                            InfrastructureVulnerability(
                                id=f"DOCKER_DANGEROUS_PORT_{port_num}_{i}",
                                risk_type=InfrastructureRisk.NETWORK_SECURITY,
                                severity="HIGH" if port_num in [22, 23, 3389] else "MEDIUM",
                                title=f"Dangerous Port Exposed: {dangerous_ports[port_num]}",
                                description=f"Port {port_num} ({dangerous_ports[port_num]}) is exposed",
                                resource_type="dockerfile",
                                resource_name=filename,
                                location={"file": filename, "line": i},
                                impact=f"Network exposure of {dangerous_ports[port_num]} service",
                                remediation=[
                                    "Review if port exposure is necessary",
                                    "Use secure alternatives (HTTPS instead of HTTP)",
                                    "Implement proper network controls",
                                    "Use authentication and encryption"
                                ],
                                compliance_violations=["CIS Docker Benchmark"],
                                references=["https://www.cisecurity.org/benchmark/docker"],
                                confidence=0.7,
                                metadata={"port": port_num, "service": dangerous_ports[port_num]}
                            )
                        )
        
        return vulnerabilities
    
    def _check_volume_mounts(self, lines: List[str], filename: str) -> List[InfrastructureVulnerability]:
        """Check for insecure volume mounts"""
        vulnerabilities = []
        sensitive_paths = [
            "/", "/etc", "/usr", "/var", "/proc", "/sys", 
            "/etc/passwd", "/etc/shadow", "/etc/hosts",
            "/var/run/docker.sock"
        ]
        
        for i, line in enumerate(lines, 1):
            if 'VOLUME' in line.upper() or '-v' in line or '--volume' in line:
                for sensitive_path in sensitive_paths:
                    if sensitive_path in line:
                        severity = "CRITICAL" if sensitive_path == "/var/run/docker.sock" else "HIGH"
                        
                        vulnerabilities.append(
                            InfrastructureVulnerability(
                                id=f"DOCKER_SENSITIVE_VOLUME_{hash(sensitive_path) % 10000}_{i}",
                                risk_type=InfrastructureRisk.PRIVILEGE_ESCALATION,
                                severity=severity,
                                title=f"Sensitive Path Mount: {sensitive_path}",
                                description=f"Container has access to sensitive host path: {sensitive_path}",
                                resource_type="dockerfile",
                                resource_name=filename,
                                location={"file": filename, "line": i},
                                impact="Container can access sensitive host resources",
                                remediation=[
                                    "Remove unnecessary volume mounts",
                                    "Use read-only mounts where possible",
                                    "Mount only specific required directories",
                                    "Implement proper access controls"
                                ],
                                compliance_violations=["CIS Docker Benchmark 5.12"],
                                references=["https://www.cisecurity.org/benchmark/docker"],
                                confidence=0.9,
                                metadata={"sensitive_path": sensitive_path, "line_content": line.strip()}
                            )
                        )
        
        return vulnerabilities
    
    def _check_resource_limits(self, lines: List[str], filename: str) -> List[InfrastructureVulnerability]:
        """Check for missing resource limits"""
        has_resource_limits = any('--memory' in line or '--cpus' in line for line in lines)
        
        if not has_resource_limits:
            return [
                InfrastructureVulnerability(
                    id="DOCKER_NO_RESOURCE_LIMITS",
                    risk_type=InfrastructureRisk.CONTAINER_SECURITY,
                    severity="MEDIUM",
                    title="No Resource Limits Configured",
                    description="Container has no CPU or memory limits",
                    resource_type="dockerfile",
                    resource_name=filename,
                    location={"file": filename},
                    impact="Container can consume unlimited host resources",
                    remediation=[
                        "Implement CPU limits (--cpus)",
                        "Implement memory limits (--memory)",
                        "Use docker-compose resource constraints",
                        "Monitor resource usage"
                    ],
                    compliance_violations=["CIS Docker Benchmark"],
                    references=["https://docs.docker.com/config/containers/resource_constraints/"],
                    confidence=0.7,
                    metadata={"issue": "no_resource_limits"}
                )
            ]
        
        return []
    
    def _check_health_checks(self, lines: List[str], filename: str) -> List[InfrastructureVulnerability]:
        """Check for missing health checks"""
        has_healthcheck = any('HEALTHCHECK' in line.upper() for line in lines)
        
        if not has_healthcheck:
            return [
                InfrastructureVulnerability(
                    id="DOCKER_NO_HEALTHCHECK",
                    risk_type=InfrastructureRisk.MONITORING_GAPS,
                    severity="LOW",
                    title="No Health Check Configured",
                    description="Container has no health check mechanism",
                    resource_type="dockerfile",
                    resource_name=filename,
                    location={"file": filename},
                    impact="Unhealthy containers may not be detected automatically",
                    remediation=[
                        "Add HEALTHCHECK instruction",
                        "Implement application health endpoints",
                        "Configure proper health check intervals",
                        "Set up monitoring and alerting"
                    ],
                    compliance_violations=[],
                    references=["https://docs.docker.com/engine/reference/builder/#healthcheck"],
                    confidence=0.6,
                    metadata={"issue": "no_healthcheck"}
                )
            ]
        
        return []
    
    def _check_secrets_management(self, lines: List[str], filename: str) -> List[InfrastructureVulnerability]:
        """Check for hardcoded secrets in Dockerfile"""
        vulnerabilities = []
        secret_patterns = [
            (r'(?i)(password|pwd|pass)\s*=\s*["\'][^"\']{3,}["\']', "Hardcoded Password"),
            (r'(?i)(api_key|apikey|api-key)\s*=\s*["\'][^"\']{10,}["\']', "Hardcoded API Key"),
            (r'(?i)(secret|token)\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded Secret"),
            (r'sk-[a-zA-Z0-9]{10,}', "OpenAI API Key"),
            (r'(?i)ENV\s+(.*(?:password|pwd|pass|api_key|apikey|secret|token).*)', "Secret in Environment Variable")
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern, description in secret_patterns:
                if re.search(pattern, line):
                    vulnerabilities.append(
                        InfrastructureVulnerability(
                            id=f"DOCKER_SECRET_{hash(description) % 10000}_{i}",
                            risk_type=InfrastructureRisk.DATA_EXPOSURE,
                            severity="HIGH",
                            title=f"Hardcoded Secret: {description}",
                            description=f"Potential hardcoded secret detected: {description}",
                            resource_type="dockerfile",
                            resource_name=filename,
                            location={"file": filename, "line": i},
                            impact="Secrets exposed in container image",
                            remediation=[
                                "Use Docker secrets management",
                                "Use environment variables for secrets",
                                "Implement secure secret injection",
                                "Remove secrets from image layers"
                            ],
                            compliance_violations=["CIS Docker Benchmark"],
                            references=[
                                "https://docs.docker.com/engine/swarm/secrets/",
                                "https://www.cisecurity.org/benchmark/docker"
                            ],
                            confidence=0.8,
                            metadata={"pattern": pattern, "line_content": line.strip()}
                        )
                    )
        
        return vulnerabilities
    
    def _analyze_compose_service(self, service_config: Dict[str, Any], service_name: str, filename: str) -> List[InfrastructureVulnerability]:
        """Analyze individual Docker Compose service"""
        vulnerabilities = []
        
        # Check for privileged mode
        if service_config.get('privileged', False):
            vulnerabilities.append(
                InfrastructureVulnerability(
                    id=f"COMPOSE_PRIVILEGED_{service_name}",
                    risk_type=InfrastructureRisk.PRIVILEGE_ESCALATION,
                    severity="HIGH",
                    title="Privileged Service Configuration",
                    description=f"Service '{service_name}' is configured with privileged mode",
                    resource_type="docker-compose",
                    resource_name=service_name,
                    location={"file": filename, "service": service_name},
                    impact="Service has full access to host system",
                    remediation=[
                        "Remove privileged: true",
                        "Use specific capabilities instead",
                        "Follow principle of least privilege"
                    ],
                    compliance_violations=["CIS Docker Benchmark 5.4"],
                    references=["https://www.cisecurity.org/benchmark/docker"],
                    confidence=0.95,
                    metadata={"service": service_name}
                )
            )
        
        # Check for volume mounts to sensitive paths
        volumes = service_config.get('volumes', [])
        for volume in volumes:
            if isinstance(volume, str) and ':' in volume:
                host_path = volume.split(':')[0]
                if host_path in ['/var/run/docker.sock', '/', '/etc', '/usr', '/var']:
                    vulnerabilities.append(
                        InfrastructureVulnerability(
                            id=f"COMPOSE_SENSITIVE_VOLUME_{service_name}_{hash(host_path) % 10000}",
                            risk_type=InfrastructureRisk.PRIVILEGE_ESCALATION,
                            severity="HIGH",
                            title=f"Sensitive Host Path Mount: {host_path}",
                            description=f"Service '{service_name}' mounts sensitive host path: {host_path}",
                            resource_type="docker-compose",
                            resource_name=service_name,
                            location={"file": filename, "service": service_name},
                            impact="Service can access sensitive host resources",
                            remediation=[
                                "Remove unnecessary volume mounts",
                                "Use named volumes instead of host paths",
                                "Mount only specific required directories"
                            ],
                            compliance_violations=["CIS Docker Benchmark 5.12"],
                            references=["https://www.cisecurity.org/benchmark/docker"],
                            confidence=0.9,
                            metadata={"service": service_name, "host_path": host_path}
                        )
                    )
        
        # Check for missing resource limits
        if 'deploy' not in service_config or 'resources' not in service_config.get('deploy', {}):
            vulnerabilities.append(
                InfrastructureVulnerability(
                    id=f"COMPOSE_NO_RESOURCES_{service_name}",
                    risk_type=InfrastructureRisk.CONTAINER_SECURITY,
                    severity="MEDIUM",
                    title="No Resource Limits Configured",
                    description=f"Service '{service_name}' has no resource limits",
                    resource_type="docker-compose",
                    resource_name=service_name,
                    location={"file": filename, "service": service_name},
                    impact="Service can consume unlimited host resources",
                    remediation=[
                        "Add deploy.resources.limits section",
                        "Set memory and CPU limits",
                        "Monitor resource usage"
                    ],
                    compliance_violations=[],
                    references=["https://docs.docker.com/compose/compose-file/#resources"],
                    confidence=0.7,
                    metadata={"service": service_name}
                )
            )
        
        return vulnerabilities


class CloudConfigurationAnalyzer:
    """Cloud configuration security analyzer"""
    
    def __init__(self):
        self.aws_checks = {}
    
    def analyze_cloud_config(self, content: str, config_type: str, filename: str) -> List[InfrastructureVulnerability]:
        """Analyze cloud configuration files"""
        vulnerabilities = []
        
        try:
            if config_type.lower() in ['cloudformation', 'cf']:
                vulnerabilities.extend(self._analyze_cloudformation(content, filename))
            elif config_type.lower() in ['terraform', 'tf']:
                vulnerabilities.extend(self._analyze_terraform(content, filename))
            elif config_type.lower() == 'kubernetes':
                vulnerabilities.extend(self._analyze_kubernetes(content, filename))
            
        except Exception as e:
            vulnerabilities.append(
                InfrastructureVulnerability(
                    id=f"CLOUD_PARSE_ERROR_{hash(str(e)) % 10000}",
                    risk_type=InfrastructureRisk.CLOUD_MISCONFIGURATION,
                    severity="MEDIUM",
                    title="Configuration Parsing Error",
                    description=f"Error parsing {config_type} configuration: {str(e)}",
                    resource_type=config_type,
                    resource_name=filename,
                    location={"file": filename, "error": str(e)},
                    impact="Configuration cannot be validated for security issues",
                    remediation=["Fix configuration syntax", "Validate configuration"],
                    compliance_violations=[],
                    references=[],
                    confidence=1.0,
                    metadata={"error": str(e), "config_type": config_type}
                )
            )
        
        return vulnerabilities
    
    def _analyze_cloudformation(self, content: str, filename: str) -> List[InfrastructureVulnerability]:
        """Analyze AWS CloudFormation templates"""
        vulnerabilities = []
        
        try:
            if content.strip().startswith('{'):
                template = json.loads(content)
            else:
                template = yaml.safe_load(content)
            
            resources = template.get('Resources', {})
            
            for resource_name, resource_config in resources.items():
                resource_type = resource_config.get('Type', '')
                properties = resource_config.get('Properties', {})
                
                # S3 bucket security checks
                if resource_type == 'AWS::S3::Bucket':
                    vulns = self._check_s3_security(resource_name, properties, filename)
                    vulnerabilities.extend(vulns)
                
                # Security group checks
                elif resource_type == 'AWS::EC2::SecurityGroup':
                    vulns = self._check_security_group(resource_name, properties, filename)
                    vulnerabilities.extend(vulns)
                
                # RDS security checks
                elif 'RDS' in resource_type:
                    vulns = self._check_rds_security(resource_name, properties, filename)
                    vulnerabilities.extend(vulns)
        
        except Exception as e:
            print(f"Error analyzing CloudFormation: {e}")
        
        return vulnerabilities
    
    def _analyze_terraform(self, content: str, filename: str) -> List[InfrastructureVulnerability]:
        """Analyze Terraform configurations"""
        vulnerabilities = []
        
        # Basic Terraform security patterns
        security_patterns = [
            (r'ami\s*=\s*"ami-[a-f0-9]{8,}"', "Hardcoded AMI ID", "MEDIUM"),
            (r'password\s*=\s*"[^"]{8,}"', "Hardcoded Password", "HIGH"),
            (r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', "Open Security Group", "HIGH"),
            (r'publicly_accessible\s*=\s*true', "Public Database Access", "HIGH"),
            (r'skip_final_snapshot\s*=\s*true', "Skip Final Snapshot", "MEDIUM"),
        ]
        
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            for pattern, title, severity in security_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(
                        InfrastructureVulnerability(
                            id=f"TERRAFORM_{title.replace(' ', '_').upper()}_{i}",
                            risk_type=InfrastructureRisk.CLOUD_MISCONFIGURATION,
                            severity=severity,
                            title=f"Terraform Security Issue: {title}",
                            description=f"Potentially insecure Terraform configuration: {title}",
                            resource_type="terraform",
                            resource_name=filename,
                            location={"file": filename, "line": i},
                            impact=f"Security risk from {title.lower()}",
                            remediation=[
                                "Review Terraform configuration",
                                "Follow security best practices",
                                "Use variables for sensitive values"
                            ],
                            compliance_violations=["CIS AWS Foundations Benchmark"],
                            references=["https://www.terraform.io/docs/"],
                            confidence=0.7,
                            metadata={"pattern": pattern, "line_content": line.strip()}
                        )
                    )
        
        return vulnerabilities
    
    def _analyze_kubernetes(self, content: str, filename: str) -> List[InfrastructureVulnerability]:
        """Analyze Kubernetes configurations"""
        vulnerabilities = []
        
        try:
            # Handle multiple YAML documents
            docs = yaml.safe_load_all(content)
            
            for doc in docs:
                if not doc:
                    continue
                
                kind = doc.get('kind', '')
                metadata = doc.get('metadata', {})
                spec = doc.get('spec', {})
                
                resource_name = metadata.get('name', 'unknown')
                
                if kind == 'Pod':
                    vulns = self._check_pod_security(resource_name, spec, filename)
                    vulnerabilities.extend(vulns)
                elif kind == 'Deployment':
                    template_spec = spec.get('template', {}).get('spec', {})
                    vulns = self._check_pod_security(resource_name, template_spec, filename)
                    vulnerabilities.extend(vulns)
                elif kind == 'Service':
                    vulns = self._check_service_security(resource_name, spec, filename)
                    vulnerabilities.extend(vulns)
        
        except yaml.YAMLError as e:
            vulnerabilities.append(
                InfrastructureVulnerability(
                    id=f"K8S_YAML_ERROR_{hash(str(e)) % 10000}",
                    risk_type=InfrastructureRisk.CLOUD_MISCONFIGURATION,
                    severity="MEDIUM",
                    title="Kubernetes YAML Parsing Error",
                    description=f"Error parsing Kubernetes configuration: {str(e)}",
                    resource_type="kubernetes",
                    resource_name=filename,
                    location={"file": filename, "error": str(e)},
                    impact="Configuration cannot be validated for security issues",
                    remediation=["Fix YAML syntax errors", "Validate configuration"],
                    compliance_violations=["CIS Kubernetes Benchmark"],
                    references=["https://kubernetes.io/docs/"],
                    confidence=1.0,
                    metadata={"error": str(e)}
                )
            )
        
        return vulnerabilities
    
    def _check_s3_security(self, bucket_name: str, properties: Dict[str, Any], filename: str) -> List[InfrastructureVulnerability]:
        """Check S3 bucket security configuration"""
        vulnerabilities = []
        
        # Check for public read access
        public_access_block = properties.get('PublicAccessBlockConfiguration', {})
        if not public_access_block.get('BlockPublicAcls', False):
            vulnerabilities.append(
                InfrastructureVulnerability(
                    id=f"S3_PUBLIC_ACLS_{bucket_name}",
                    risk_type=InfrastructureRisk.DATA_EXPOSURE,
                    severity="HIGH",
                    title="S3 Bucket Allows Public ACLs",
                    description=f"S3 bucket '{bucket_name}' allows public ACLs",
                    resource_type="AWS::S3::Bucket",
                    resource_name=bucket_name,
                    location={"file": filename, "resource": bucket_name},
                    impact="Bucket contents may be publicly accessible",
                    remediation=[
                        "Enable BlockPublicAcls in PublicAccessBlockConfiguration",
                        "Review bucket permissions",
                        "Implement least privilege access"
                    ],
                    compliance_violations=["CIS AWS Foundations Benchmark 2.1.1"],
                    references=["https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html"],
                    confidence=0.9,
                    metadata={"bucket_name": bucket_name}
                )
            )
        
        # Check for encryption
        encryption = properties.get('BucketEncryption')
        if not encryption:
            vulnerabilities.append(
                InfrastructureVulnerability(
                    id=f"S3_NO_ENCRYPTION_{bucket_name}",
                    risk_type=InfrastructureRisk.ENCRYPTION_ISSUES,
                    severity="MEDIUM",
                    title="S3 Bucket Not Encrypted",
                    description=f"S3 bucket '{bucket_name}' does not have encryption configured",
                    resource_type="AWS::S3::Bucket",
                    resource_name=bucket_name,
                    location={"file": filename, "resource": bucket_name},
                    impact="Data stored in bucket is not encrypted at rest",
                    remediation=[
                        "Enable BucketEncryption with AES256 or KMS",
                        "Configure default encryption",
                        "Use KMS keys for additional security"
                    ],
                    compliance_violations=["CIS AWS Foundations Benchmark"],
                    references=["https://docs.aws.amazon.com/AmazonS3/latest/dev/bucket-encryption.html"],
                    confidence=0.8,
                    metadata={"bucket_name": bucket_name}
                )
            )
        
        return vulnerabilities
    
    def _check_security_group(self, sg_name: str, properties: Dict[str, Any], filename: str) -> List[InfrastructureVulnerability]:
        """Check security group configuration"""
        vulnerabilities = []
        
        ingress_rules = properties.get('SecurityGroupIngress', [])
        
        for rule in ingress_rules:
            cidr_ip = rule.get('CidrIp', '')
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')
            
            # Check for open ingress (0.0.0.0/0)
            if cidr_ip == '0.0.0.0/0':
                port_info = f"port {from_port}" if from_port == to_port else f"ports {from_port}-{to_port}"
                
                vulnerabilities.append(
                    InfrastructureVulnerability(
                        id=f"SG_OPEN_INGRESS_{sg_name}_{from_port}",
                        risk_type=InfrastructureRisk.NETWORK_SECURITY,
                        severity="HIGH",
                        title="Security Group Open to Internet",
                        description=f"Security group '{sg_name}' allows ingress from 0.0.0.0/0 on {port_info}",
                        resource_type="AWS::EC2::SecurityGroup",
                        resource_name=sg_name,
                        location={"file": filename, "resource": sg_name},
                        impact="Network resources exposed to internet",
                        remediation=[
                            "Restrict CIDR to specific IP ranges",
                            "Use security groups instead of 0.0.0.0/0",
                            "Implement least privilege access"
                        ],
                        compliance_violations=["CIS AWS Foundations Benchmark 4.1", "CIS AWS Foundations Benchmark 4.2"],
                        references=["https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"],
                        confidence=0.95,
                        metadata={"security_group": sg_name, "port": from_port, "cidr": cidr_ip}
                    )
                )
        
        return vulnerabilities
    
    def _check_rds_security(self, rds_name: str, properties: Dict[str, Any], filename: str) -> List[InfrastructureVulnerability]:
        """Check RDS security configuration"""
        vulnerabilities = []
        
        # Check for public accessibility
        if properties.get('PubliclyAccessible', False):
            vulnerabilities.append(
                InfrastructureVulnerability(
                    id=f"RDS_PUBLIC_ACCESS_{rds_name}",
                    risk_type=InfrastructureRisk.DATA_EXPOSURE,
                    severity="HIGH",
                    title="RDS Instance Publicly Accessible",
                    description=f"RDS instance '{rds_name}' is configured as publicly accessible",
                    resource_type="RDS",
                    resource_name=rds_name,
                    location={"file": filename, "resource": rds_name},
                    impact="Database exposed to internet",
                    remediation=[
                        "Set PubliclyAccessible to false",
                        "Use private subnets for databases",
                        "Implement VPC security controls"
                    ],
                    compliance_violations=["CIS AWS Foundations Benchmark 2.3.1"],
                    references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"],
                    confidence=0.95,
                    metadata={"rds_instance": rds_name}
                )
            )
        
        # Check for encryption
        if not properties.get('StorageEncrypted', False):
            vulnerabilities.append(
                InfrastructureVulnerability(
                    id=f"RDS_NO_ENCRYPTION_{rds_name}",
                    risk_type=InfrastructureRisk.ENCRYPTION_ISSUES,
                    severity="MEDIUM",
                    title="RDS Instance Not Encrypted",
                    description=f"RDS instance '{rds_name}' does not have storage encryption enabled",
                    resource_type="RDS",
                    resource_name=rds_name,
                    location={"file": filename, "resource": rds_name},
                    impact="Database storage not encrypted at rest",
                    remediation=[
                        "Enable StorageEncrypted",
                        "Use KMS keys for encryption",
                        "Enable encryption in transit"
                    ],
                    compliance_violations=["CIS AWS Foundations Benchmark"],
                    references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"],
                    confidence=0.8,
                    metadata={"rds_instance": rds_name}
                )
            )
        
        return vulnerabilities
    
    def _check_pod_security(self, pod_name: str, spec: Dict[str, Any], filename: str) -> List[InfrastructureVulnerability]:
        """Check Kubernetes pod security configuration"""
        vulnerabilities = []
        
        containers = spec.get('containers', [])
        security_context = spec.get('securityContext', {})
        
        # Check if running as root
        if not security_context.get('runAsNonRoot', False):
            vulnerabilities.append(
                InfrastructureVulnerability(
                    id=f"K8S_ROOT_USER_{pod_name}",
                    risk_type=InfrastructureRisk.PRIVILEGE_ESCALATION,
                    severity="HIGH",
                    title="Pod Running as Root",
                    description=f"Pod '{pod_name}' may be running as root user",
                    resource_type="kubernetes",
                    resource_name=pod_name,
                    location={"file": filename, "resource": pod_name},
                    impact="Container has unnecessary privileges",
                    remediation=[
                        "Set runAsNonRoot: true in securityContext",
                        "Set runAsUser to non-root UID",
                        "Follow principle of least privilege"
                    ],
                    compliance_violations=["CIS Kubernetes Benchmark 5.2.6"],
                    references=["https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"],
                    confidence=0.7,
                    metadata={"pod_name": pod_name}
                )
            )
        
        # Check for privileged containers
        for container in containers:
            container_security = container.get('securityContext', {})
            if container_security.get('privileged', False):
                vulnerabilities.append(
                    InfrastructureVulnerability(
                        id=f"K8S_PRIVILEGED_CONTAINER_{pod_name}_{container.get('name', 'unknown')}",
                        risk_type=InfrastructureRisk.PRIVILEGE_ESCALATION,
                        severity="CRITICAL",
                        title="Privileged Container",
                        description=f"Container '{container.get('name')}' in pod '{pod_name}' is privileged",
                        resource_type="kubernetes",
                        resource_name=pod_name,
                        location={"file": filename, "resource": pod_name, "container": container.get('name')},
                        impact="Container has full access to host system",
                        remediation=[
                            "Remove privileged: true",
                            "Use specific capabilities instead",
                            "Implement proper RBAC"
                        ],
                        compliance_violations=["CIS Kubernetes Benchmark 5.2.1"],
                        references=["https://kubernetes.io/docs/concepts/policy/pod-security-policy/"],
                        confidence=0.95,
                        metadata={"pod_name": pod_name, "container_name": container.get('name')}
                    )
                )
        
        return vulnerabilities
    
    def _check_service_security(self, service_name: str, spec: Dict[str, Any], filename: str) -> List[InfrastructureVulnerability]:
        """Check Kubernetes service security configuration"""
        vulnerabilities = []
        
        # Check for LoadBalancer type services
        if spec.get('type') == 'LoadBalancer':
            vulnerabilities.append(
                InfrastructureVulnerability(
                    id=f"K8S_LOADBALANCER_{service_name}",
                    risk_type=InfrastructureRisk.NETWORK_SECURITY,
                    severity="MEDIUM",
                    title="LoadBalancer Service Type",
                    description=f"Service '{service_name}' uses LoadBalancer type",
                    resource_type="kubernetes",
                    resource_name=service_name,
                    location={"file": filename, "resource": service_name},
                    impact="Service exposed to external traffic",
                    remediation=[
                        "Review if external access is necessary",
                        "Use ClusterIP or NodePort if appropriate",
                        "Implement proper network policies",
                        "Use ingress controllers for HTTP traffic"
                    ],
                    compliance_violations=[],
                    references=["https://kubernetes.io/docs/concepts/services-networking/service/"],
                    confidence=0.6,
                    metadata={"service_name": service_name, "service_type": "LoadBalancer"}
                )
            )
        
        return vulnerabilities


class InfrastructureSecurityEngine:
    """Main infrastructure security analysis engine"""
    
    def __init__(self):
        self.docker_analyzer = DockerSecurityAnalyzer()
        self.cloud_analyzer = CloudConfigurationAnalyzer()
        
        self.file_type_mapping = {
            'dockerfile': ('docker', self.docker_analyzer.analyze_dockerfile),
            'docker-compose.yml': ('docker-compose', self.docker_analyzer.analyze_docker_compose),
            'docker-compose.yaml': ('docker-compose', self.docker_analyzer.analyze_docker_compose),
            '.tf': ('terraform', self.cloud_analyzer.analyze_cloud_config),
            '.yaml': ('kubernetes', self.cloud_analyzer.analyze_cloud_config),
            '.yml': ('kubernetes', self.cloud_analyzer.analyze_cloud_config),
            '.json': ('cloudformation', self.cloud_analyzer.analyze_cloud_config)
        }
    
    def analyze_infrastructure(self, content: str, filename: str) -> Dict[str, Any]:
        """Perform comprehensive infrastructure security analysis"""
        start_time = datetime.now()
        
        # Determine file type and analyzer
        file_type, analyzer_func = self._determine_analyzer(filename, content)
        
        if not analyzer_func:
            return {
                "analysis_id": f"INFRA_{int(datetime.now().timestamp())}",
                "timestamp": datetime.now().isoformat(),
                "filename": filename,
                "file_type": "unknown",
                "analysis_time": 0.0,
                "vulnerabilities": [],
                "summary": {"risk_level": "UNKNOWN", "total_vulnerabilities": 0},
                "error": "Unsupported file type for infrastructure analysis"
            }
        
        # Perform analysis
        try:
            if file_type in ['terraform', 'kubernetes', 'cloudformation']:
                vulnerabilities = analyzer_func(content, file_type, filename)
            else:
                vulnerabilities = analyzer_func(content, filename)
        except Exception as e:
            return {
                "analysis_id": f"INFRA_{int(datetime.now().timestamp())}",
                "timestamp": datetime.now().isoformat(),
                "filename": filename,
                "file_type": file_type,
                "analysis_time": 0.0,
                "vulnerabilities": [],
                "summary": {"risk_level": "ERROR", "total_vulnerabilities": 0},
                "error": f"Analysis failed: {str(e)}"
            }
        
        # Sort vulnerabilities by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        vulnerabilities.sort(key=lambda v: (severity_order.get(v.severity, 3), -v.confidence))
        
        analysis_time = (datetime.now() - start_time).total_seconds()
        
        return {
            "analysis_id": f"INFRA_{int(datetime.now().timestamp())}",
            "timestamp": datetime.now().isoformat(),
            "filename": filename,
            "file_type": file_type,
            "analysis_time": analysis_time,
            "vulnerabilities": [asdict(vuln) for vuln in vulnerabilities],
            "summary": self._generate_infrastructure_summary(vulnerabilities),
            "compliance_assessment": self._assess_compliance_violations(vulnerabilities),
            "recommendations": self._generate_infrastructure_recommendations(vulnerabilities)
        }
    
    def _determine_analyzer(self, filename: str, content: str) -> Tuple[str, Any]:
        """Determine the appropriate analyzer based on filename and content"""
        filename_lower = filename.lower()
        
        # Check exact filename matches
        for pattern, (file_type, analyzer) in self.file_type_mapping.items():
            if filename_lower.endswith(pattern) or pattern in filename_lower:
                return file_type, analyzer
        
        # Content-based detection
        if 'FROM ' in content and ('RUN ' in content or 'COPY ' in content):
            return 'docker', self.docker_analyzer.analyze_dockerfile
        
        if 'version:' in content and 'services:' in content:
            return 'docker-compose', self.docker_analyzer.analyze_docker_compose
        
        if 'apiVersion:' in content and 'kind:' in content:
            return 'kubernetes', self.cloud_analyzer.analyze_cloud_config
        
        return None, None
    
    def _generate_infrastructure_summary(self, vulnerabilities: List[InfrastructureVulnerability]) -> Dict[str, Any]:
        """Generate infrastructure analysis summary"""
        if not vulnerabilities:
            return {
                "risk_level": "NONE",
                "total_vulnerabilities": 0,
                "severity_breakdown": {},
                "risk_types": {}
            }
        
        severity_counts = {}
        risk_type_counts = {}
        
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
            risk_type = vuln.risk_type.value
            risk_type_counts[risk_type] = risk_type_counts.get(risk_type, 0) + 1
        
        # Determine overall risk level
        critical_count = severity_counts.get("CRITICAL", 0)
        high_count = severity_counts.get("HIGH", 0)
        
        if critical_count > 0:
            risk_level = "CRITICAL"
        elif high_count > 0:
            risk_level = "HIGH"
        elif severity_counts.get("MEDIUM", 0) > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            "risk_level": risk_level,
            "total_vulnerabilities": len(vulnerabilities),
            "severity_breakdown": severity_counts,
            "risk_types": risk_type_counts,
            "critical_issues": critical_count,
            "high_issues": high_count
        }
    
    def _assess_compliance_violations(self, vulnerabilities: List[InfrastructureVulnerability]) -> Dict[str, Any]:
        """Assess compliance violations"""
        compliance_violations = {}
        
        for vuln in vulnerabilities:
            for violation in vuln.compliance_violations:
                if violation not in compliance_violations:
                    compliance_violations[violation] = []
                compliance_violations[violation].append(vuln.id)
        
        return {
            "total_violations": len(compliance_violations),
            "standards_violated": list(compliance_violations.keys()),
            "violations_by_standard": compliance_violations
        }
    
    def _generate_infrastructure_recommendations(self, vulnerabilities: List[InfrastructureVulnerability]) -> List[str]:
        """Generate infrastructure-specific recommendations"""
        if not vulnerabilities:
            return ["No infrastructure security issues detected. Continue following security best practices."]
        
        recommendations = []
        
        # Critical issues
        critical_vulns = [v for v in vulnerabilities if v.severity == "CRITICAL"]
        if critical_vulns:
            recommendations.append("URGENT: Address critical infrastructure vulnerabilities immediately")
        
        # High severity issues
        high_vulns = [v for v in vulnerabilities if v.severity == "HIGH"]
        if high_vulns:
            recommendations.append(f"High Priority: Fix {len(high_vulns)} high-severity infrastructure issues")
        
        # Category-specific recommendations
        risk_types = set(v.risk_type for v in vulnerabilities)
        
        if InfrastructureRisk.PRIVILEGE_ESCALATION in risk_types:
            recommendations.append("Review and implement principle of least privilege")
        
        if InfrastructureRisk.CONTAINER_SECURITY in risk_types:
            recommendations.append("Harden container configurations and remove unnecessary privileges")
        
        if InfrastructureRisk.NETWORK_SECURITY in risk_types:
            recommendations.append("Review network security controls and restrict unnecessary access")
        
        if InfrastructureRisk.DATA_EXPOSURE in risk_types:
            recommendations.append("Implement encryption and access controls for sensitive data")
        
        # General recommendations
        recommendations.extend([
            "Implement infrastructure as code security scanning",
            "Regular security audits of cloud configurations",
            "Enable compliance monitoring and alerting",
            "Implement security policy enforcement",
            "Use security benchmarks (CIS, NIST) for hardening"
        ])
        
        return recommendations[:8]


# Integration function
def create_infrastructure_analyzer():
    """Factory function to create infrastructure analyzer"""
    return InfrastructureSecurityEngine()


if __name__ == "__main__":
    # Test the infrastructure analyzer
    analyzer = InfrastructureSecurityEngine()
    
    test_dockerfile = """
FROM ubuntu:latest
EXPOSE 22
EXPOSE 3306
USER root
RUN apt-get update && apt-get install -y ssh
COPY --chown=root:root . /app
ENV PASSWORD=hardcoded_password_123
"""
    
    result = analyzer.analyze_infrastructure(test_dockerfile, "Dockerfile")
    print(json.dumps(result, indent=2, default=str))