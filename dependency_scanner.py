

import json
import re
import hashlib
import requests
import subprocess
import tempfile
import os
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta
import concurrent.futures
from pathlib import Path


class DependencyRisk(Enum):
    """Dependency-specific risk categories"""
    KNOWN_VULNERABILITY = "known_vulnerability"
    OUTDATED_PACKAGE = "outdated_package" 
    MALICIOUS_PACKAGE = "malicious_package"
    LICENSE_VIOLATION = "license_violation"
    SUPPLY_CHAIN_ATTACK = "supply_chain_attack"
    ABANDONED_PACKAGE = "abandoned_package"
    TYPOSQUATTING = "typosquatting"
    DEPENDENCY_CONFUSION = "dependency_confusion"


@dataclass
class PackageInfo:
    """Package information structure"""
    name: str
    version: str
    latest_version: Optional[str] = None
    ecosystem: str = "pypi"  # pypi, npm, maven, etc.
    description: Optional[str] = None
    maintainers: List[str] = None
    download_count: Optional[int] = None
    last_updated: Optional[datetime] = None
    license: Optional[str] = None
    homepage: Optional[str] = None
    repository: Optional[str] = None


@dataclass
class Vulnerability:
    """CVE vulnerability information"""
    cve_id: str
    severity: str
    cvss_score: float
    description: str
    affected_versions: List[str]
    fixed_version: Optional[str]
    published_date: datetime
    references: List[str]
    cwe_ids: List[str]


@dataclass
class DependencyVulnerability:
    """Complete dependency vulnerability assessment"""
    package: PackageInfo
    risk_type: DependencyRisk
    severity: str
    cvss_score: float
    title: str
    description: str
    impact: str
    remediation: List[str]
    vulnerabilities: List[Vulnerability] = None
    confidence: float = 0.8
    metadata: Dict[str, Any] = None


class VulnerabilityDatabase:
    """Interface to vulnerability databases"""
    
    def __init__(self):
        self.osv_api_url = "https://api.osv.dev/v1"
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache = {}
        self.cache_duration = timedelta(hours=6)  # Cache for 6 hours
    
    def query_osv_vulnerabilities(self, package_name: str, version: str, ecosystem: str = "PyPI") -> List[Vulnerability]:
        """Query OSV database for vulnerabilities"""
        cache_key = f"{ecosystem}:{package_name}:{version}"
        
        # Check cache first
        if cache_key in self.cache:
            cached_data, cached_time = self.cache[cache_key]
            if datetime.now() - cached_time < self.cache_duration:
                return cached_data
        
        try:
            # Query OSV API
            query_data = {
                "version": version,
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem
                }
            }
            
            response = requests.post(
                f"{self.osv_api_url}/query",
                json=query_data,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = []
                
                for vuln_data in data.get("vulns", []):
                    vuln = self._parse_osv_vulnerability(vuln_data)
                    if vuln:
                        vulnerabilities.append(vuln)
                
                # Cache results
                self.cache[cache_key] = (vulnerabilities, datetime.now())
                return vulnerabilities
            
        except Exception as e:
            print(f"Error querying OSV database: {e}")
        
        return []
    
    def _parse_osv_vulnerability(self, vuln_data: Dict[str, Any]) -> Optional[Vulnerability]:
        """Parse OSV vulnerability data"""
        try:
            # Extract severity information
            severity_info = vuln_data.get("severity", [])
            cvss_score = 0.0
            severity = "UNKNOWN"
            
            for sev in severity_info:
                if sev.get("type") == "CVSS_V3":
                    cvss_score = float(sev.get("score", 0.0))
                    if cvss_score >= 9.0:
                        severity = "CRITICAL"
                    elif cvss_score >= 7.0:
                        severity = "HIGH"
                    elif cvss_score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                    break
            
            # Extract affected versions
            affected_versions = []
            for affected in vuln_data.get("affected", []):
                versions = affected.get("versions", [])
                affected_versions.extend(versions)
            
            # Extract fixed version
            fixed_version = None
            for affected in vuln_data.get("affected", []):
                ranges = affected.get("ranges", [])
                for range_info in ranges:
                    events = range_info.get("events", [])
                    for event in events:
                        if "fixed" in event:
                            fixed_version = event["fixed"]
                            break
                    if fixed_version:
                        break
            
            # Extract references
            references = []
            for ref in vuln_data.get("references", []):
                if "url" in ref:
                    references.append(ref["url"])
            
            # Extract CWE IDs
            cwe_ids = []
            database_specific = vuln_data.get("database_specific", {})
            if "cwe_ids" in database_specific:
                cwe_ids = database_specific["cwe_ids"]
            
            # Parse publication date
            published_date = datetime.now()
            if "published" in vuln_data:
                try:
                    published_date = datetime.fromisoformat(
                        vuln_data["published"].replace("Z", "+00:00")
                    )
                except:
                    pass
            
            return Vulnerability(
                cve_id=vuln_data.get("id", "UNKNOWN"),
                severity=severity,
                cvss_score=cvss_score,
                description=vuln_data.get("summary", "No description available"),
                affected_versions=affected_versions,
                fixed_version=fixed_version,
                published_date=published_date,
                references=references,
                cwe_ids=cwe_ids
            )
        
        except Exception as e:
            print(f"Error parsing OSV vulnerability: {e}")
            return None


class PackageIntelligence:
    """Package intelligence and metadata analysis"""
    
    def __init__(self):
        self.pypi_api_url = "https://pypi.org/pypi"
        self.npm_api_url = "https://registry.npmjs.org"
        self.suspicious_patterns = [
            r'(?i)(bitcoin|crypto|wallet|mining)',  # Cryptocurrency related
            r'(?i)(password|auth|login|credential)',  # Authentication related
            r'(?i)(eval|exec|system|shell)',  # Code execution
            r'(?i)(download|fetch|curl|wget)',  # Network activity
        ]
    
    def get_package_info(self, package_name: str, ecosystem: str = "pypi") -> Optional[PackageInfo]:
        """Get comprehensive package information"""
        try:
            if ecosystem.lower() == "pypi":
                return self._get_pypi_package_info(package_name)
            elif ecosystem.lower() == "npm":
                return self._get_npm_package_info(package_name)
            else:
                return PackageInfo(name=package_name, version="unknown", ecosystem=ecosystem)
        except Exception as e:
            print(f"Error getting package info for {package_name}: {e}")
            return None
    
    def _get_pypi_package_info(self, package_name: str) -> Optional[PackageInfo]:
        """Get PyPI package information"""
        try:
            response = requests.get(f"{self.pypi_api_url}/{package_name}/json", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                info = data.get("info", {})
                
                # Get maintainers
                maintainers = []
                if "maintainer" in info and info["maintainer"]:
                    maintainers.append(info["maintainer"])
                if "author" in info and info["author"]:
                    maintainers.append(info["author"])
                
                # Get last updated date
                last_updated = None
                releases = data.get("releases", {})
                if releases:
                    latest_version = max(releases.keys(), key=lambda x: releases[x][-1]["upload_time"] if releases[x] else "")
                    if latest_version and releases[latest_version]:
                        try:
                            last_updated = datetime.fromisoformat(
                                releases[latest_version][-1]["upload_time"].replace("Z", "+00:00")
                            )
                        except:
                            pass
                
                return PackageInfo(
                    name=package_name,
                    version=info.get("version", "unknown"),
                    latest_version=info.get("version"),
                    ecosystem="pypi",
                    description=info.get("summary", ""),
                    maintainers=maintainers,
                    download_count=None,  # Not available in basic API
                    last_updated=last_updated,
                    license=info.get("license", ""),
                    homepage=info.get("home_page", ""),
                    repository=info.get("project_urls", {}).get("Repository", "")
                )
        except Exception as e:
            print(f"Error fetching PyPI info for {package_name}: {e}")
        
        return None
    
    def _get_npm_package_info(self, package_name: str) -> Optional[PackageInfo]:
        """Get NPM package information"""
        try:
            response = requests.get(f"{self.npm_api_url}/{package_name}", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                latest_version = data.get("dist-tags", {}).get("latest", "unknown")
                version_info = data.get("versions", {}).get(latest_version, {})
                
                # Get maintainers
                maintainers = []
                if "maintainers" in data:
                    maintainers = [m.get("name", "") for m in data["maintainers"]]
                
                # Get last updated
                last_updated = None
                if "time" in data and "modified" in data["time"]:
                    try:
                        last_updated = datetime.fromisoformat(
                            data["time"]["modified"].replace("Z", "+00:00")
                        )
                    except:
                        pass
                
                return PackageInfo(
                    name=package_name,
                    version=latest_version,
                    latest_version=latest_version,
                    ecosystem="npm",
                    description=data.get("description", ""),
                    maintainers=maintainers,
                    download_count=None,
                    last_updated=last_updated,
                    license=version_info.get("license", ""),
                    homepage=data.get("homepage", ""),
                    repository=version_info.get("repository", {}).get("url", "")
                )
        except Exception as e:
            print(f"Error fetching NPM info for {package_name}: {e}")
        
        return None
    
    def detect_suspicious_package(self, package_info: PackageInfo) -> List[str]:
        """Detect suspicious package characteristics"""
        suspicious_indicators = []
        
        # Check package name for suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.search(pattern, package_info.name):
                suspicious_indicators.append(f"Suspicious name pattern: {pattern}")
        
        # Check description for suspicious content
        if package_info.description:
            for pattern in self.suspicious_patterns:
                if re.search(pattern, package_info.description):
                    suspicious_indicators.append(f"Suspicious description content: {pattern}")
        
        # Check for typosquatting (simplified check)
        if self._check_typosquatting(package_info.name):
            suspicious_indicators.append("Potential typosquatting detected")
        
        # Check for new packages (potential supply chain attack)
        if package_info.last_updated:
            days_old = (datetime.now() - package_info.last_updated.replace(tzinfo=None)).days
            if days_old < 30:
                suspicious_indicators.append("Very new package (less than 30 days old)")
        
        # Check for packages with no maintainer information
        if not package_info.maintainers or all(not m.strip() for m in package_info.maintainers):
            suspicious_indicators.append("No maintainer information available")
        
        return suspicious_indicators
    
    def _check_typosquatting(self, package_name: str) -> bool:
        """Simple typosquatting check against popular packages"""
        popular_packages = {
            "requests", "urllib3", "numpy", "pandas", "flask", "django",
            "tensorflow", "pytorch", "scikit-learn", "matplotlib", "selenium"
        }
        
        # Check for similar names (simplified Levenshtein-like check)
        for popular in popular_packages:
            if abs(len(package_name) - len(popular)) <= 2:
                # Simple character difference check
                diff_count = sum(c1 != c2 for c1, c2 in zip(package_name, popular))
                if diff_count <= 2 and package_name != popular:
                    return True
        
        return False


class DependencyScanner:
    """Main dependency vulnerability scanner"""
    
    def __init__(self):
        self.vuln_db = VulnerabilityDatabase()
        self.package_intel = PackageIntelligence()
        self.supported_files = {
            "requirements.txt": self._parse_requirements_txt,
            "Pipfile": self._parse_pipfile,
            "package.json": self._parse_package_json,
            "yarn.lock": self._parse_yarn_lock,
            "pom.xml": self._parse_pom_xml,
            "go.mod": self._parse_go_mod
        }
    
    def scan_dependencies(self, file_content: str, filename: str) -> Dict[str, Any]:
        """Perform comprehensive dependency scan"""
        start_time = datetime.now()
        
        # Parse dependencies based on file type
        dependencies = self._parse_dependency_file(file_content, filename)
        
        if not dependencies:
            return {
                "scan_id": f"DEP_{int(datetime.now().timestamp())}",
                "timestamp": datetime.now().isoformat(),
                "filename": filename,
                "scan_time": 0.0,
                "dependencies_found": 0,
                "vulnerabilities": [],
                "summary": {"risk_level": "NONE", "total_vulnerabilities": 0}
            }
        
        # Scan each dependency for vulnerabilities
        all_vulnerabilities = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_dep = {
                executor.submit(self._scan_single_dependency, dep, ecosystem):
                (dep, ecosystem) for dep, ecosystem in dependencies
            }
            
            for future in concurrent.futures.as_completed(future_to_dep):
                dep, ecosystem = future_to_dep[future]
                try:
                    vulnerabilities = future.result()
                    all_vulnerabilities.extend(vulnerabilities)
                except Exception as e:
                    print(f"Error scanning dependency {dep}: {e}")
        
        # Sort vulnerabilities by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        all_vulnerabilities.sort(key=lambda v: (severity_order.get(v.severity, 4), -v.cvss_score))
        
        scan_time = (datetime.now() - start_time).total_seconds()
        
        return {
            "scan_id": f"DEP_{int(datetime.now().timestamp())}",
            "timestamp": datetime.now().isoformat(),
            "filename": filename,
            "scan_time": scan_time,
            "dependencies_found": len(dependencies),
            "dependencies_scanned": len(set(dep for dep, _ in dependencies)),
            "vulnerabilities": [asdict(vuln) for vuln in all_vulnerabilities],
            "summary": self._generate_scan_summary(all_vulnerabilities),
            "recommendations": self._generate_dependency_recommendations(all_vulnerabilities)
        }
    
    def _parse_dependency_file(self, content: str, filename: str) -> List[Tuple[str, str]]:
        """Parse dependency file based on type"""
        file_basename = os.path.basename(filename).lower()
        
        for supported_file, parser in self.supported_files.items():
            if file_basename == supported_file or file_basename.endswith(supported_file):
                try:
                    return parser(content)
                except Exception as e:
                    print(f"Error parsing {filename}: {e}")
                    break
        
        return []
    
    def _parse_requirements_txt(self, content: str) -> List[Tuple[str, str]]:
        """Parse requirements.txt file"""
        dependencies = []
        
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('-'):
                # Handle various requirement formats
                if '==' in line:
                    name, version = line.split('==')[0:2]
                elif '>=' in line:
                    name = line.split('>=')[0]
                    version = "latest"  # We'll get latest version info
                elif '<=' in line:
                    name = line.split('<=')[0]
                    version = "latest"
                else:
                    name = line
                    version = "latest"
                
                # Clean up name
                name = re.sub(r'[^\w\-\.]', '', name.strip())
                if name:
                    dependencies.append((name, "pypi"))
        
        return dependencies
    
    def _parse_package_json(self, content: str) -> List[Tuple[str, str]]:
        """Parse package.json file"""
        try:
            data = json.loads(content)
            dependencies = []
            
            # Parse dependencies and devDependencies
            for dep_type in ["dependencies", "devDependencies"]:
                if dep_type in data:
                    for name, version in data[dep_type].items():
                        dependencies.append((name, "npm"))
            
            return dependencies
        except json.JSONDecodeError:
            return []
    
    def _parse_pipfile(self, content: str) -> List[Tuple[str, str]]:
        """Parse Pipfile"""
        dependencies = []
        current_section = None
        
        for line in content.split('\n'):
            line = line.strip()
            
            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1]
            elif current_section in ["packages", "dev-packages"] and '=' in line:
                name = line.split('=')[0].strip().strip('"')
                if name:
                    dependencies.append((name, "pypi"))
        
        return dependencies
    
    def _parse_yarn_lock(self, content: str) -> List[Tuple[str, str]]:
        """Parse yarn.lock file (simplified)"""
        dependencies = []
        
        # Extract package names from yarn.lock format
        for line in content.split('\n'):
            if '@' in line and 'version' not in line and 'resolved' not in line:
                # Extract package name from yarn.lock entry
                match = re.match(r'^"?([^@\s]+)', line.strip())
                if match:
                    name = match.group(1)
                    dependencies.append((name, "npm"))
        
        return list(set(dependencies))  # Remove duplicates
    
    def _parse_pom_xml(self, content: str) -> List[Tuple[str, str]]:
        """Parse pom.xml file (simplified)"""
        dependencies = []
        
        # Simple regex-based parsing for Maven dependencies
        dependency_pattern = r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?</dependency>'
        matches = re.findall(dependency_pattern, content, re.DOTALL)
        
        for group_id, artifact_id in matches:
            name = f"{group_id}:{artifact_id}"
            dependencies.append((name, "maven"))
        
        return dependencies
    
    def _parse_go_mod(self, content: str) -> List[Tuple[str, str]]:
        """Parse go.mod file"""
        dependencies = []
        
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('//') and not line.startswith('module'):
                # Handle "require" blocks
                if 'require' in line and '(' not in line:
                    # Single require statement
                    parts = line.replace('require', '').strip().split()
                    if parts:
                        dependencies.append((parts[0], "go"))
                elif line and not line.startswith('require') and not line.startswith(')'):
                    # Inside require block
                    parts = line.split()
                    if parts and not parts[0].startswith('//'):
                        dependencies.append((parts[0], "go"))
        
        return dependencies
    
    def _scan_single_dependency(self, package_name: str, ecosystem: str) -> List[DependencyVulnerability]:
        """Scan a single dependency for vulnerabilities"""
        vulnerabilities = []
        
        # Get package information
        package_info = self.package_intel.get_package_info(package_name, ecosystem)
        if not package_info:
            return vulnerabilities
        
        # Check for known vulnerabilities
        if ecosystem in ["pypi", "npm"]:  # OSV supports these
            osv_ecosystem = "PyPI" if ecosystem == "pypi" else "npm"
            vuln_list = self.vuln_db.query_osv_vulnerabilities(
                package_name, package_info.version, osv_ecosystem
            )
            
            for vuln in vuln_list:
                dep_vuln = DependencyVulnerability(
                    package=package_info,
                    risk_type=DependencyRisk.KNOWN_VULNERABILITY,
                    severity=vuln.severity,
                    cvss_score=vuln.cvss_score,
                    title=f"Known Vulnerability: {vuln.cve_id}",
                    description=vuln.description,
                    impact=f"Security vulnerability in {package_name} {package_info.version}",
                    remediation=[
                        f"Update to version {vuln.fixed_version}" if vuln.fixed_version else "Update to latest version",
                        "Review security advisories",
                        "Consider alternative packages if no fix available"
                    ],
                    vulnerabilities=[vuln],
                    confidence=0.95,
                    metadata={
                        "cve_id": vuln.cve_id,
                        "cwe_ids": vuln.cwe_ids,
                        "references": vuln.references
                    }
                )
                vulnerabilities.append(dep_vuln)
        
        # Check for suspicious packages
        suspicious_indicators = self.package_intel.detect_suspicious_package(package_info)
        if suspicious_indicators:
            dep_vuln = DependencyVulnerability(
                package=package_info,
                risk_type=DependencyRisk.MALICIOUS_PACKAGE,
                severity="MEDIUM",
                cvss_score=5.0,
                title="Suspicious Package Characteristics",
                description=f"Package exhibits suspicious characteristics: {', '.join(suspicious_indicators)}",
                impact="Potential supply chain security risk",
                remediation=[
                    "Review package source code",
                    "Verify package legitimacy",
                    "Consider alternative packages",
                    "Monitor package behavior"
                ],
                confidence=0.6,
                metadata={"suspicious_indicators": suspicious_indicators}
            )
            vulnerabilities.append(dep_vuln)
        
        # Check for outdated packages (simplified check)
        if package_info.last_updated:
            days_old = (datetime.now() - package_info.last_updated.replace(tzinfo=None)).days
            if days_old > 365:  # Package not updated in over a year
                dep_vuln = DependencyVulnerability(
                    package=package_info,
                    risk_type=DependencyRisk.OUTDATED_PACKAGE,
                    severity="LOW",
                    cvss_score=2.0,
                    title="Outdated Package",
                    description=f"Package has not been updated in {days_old} days",
                    impact="May contain unpatched security vulnerabilities",
                    remediation=[
                        "Update to latest version",
                        "Review package maintenance status",
                        "Consider alternative actively maintained packages"
                    ],
                    confidence=0.8,
                    metadata={"days_since_update": days_old}
                )
                vulnerabilities.append(dep_vuln)
        
        return vulnerabilities
    
    def _generate_scan_summary(self, vulnerabilities: List[DependencyVulnerability]) -> Dict[str, Any]:
        """Generate scan summary"""
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
    
    def _generate_dependency_recommendations(self, vulnerabilities: List[DependencyVulnerability]) -> List[str]:
        """Generate dependency-specific recommendations"""
        if not vulnerabilities:
            return ["No dependency vulnerabilities detected. Keep dependencies updated."]
        
        recommendations = []
        
        # Critical vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v.severity == "CRITICAL"]
        if critical_vulns:
            recommendations.append("URGENT: Update packages with critical vulnerabilities immediately")
        
        # High severity vulnerabilities
        high_vulns = [v for v in vulnerabilities if v.severity == "HIGH"]
        if high_vulns:
            recommendations.append(f"High Priority: Address {len(high_vulns)} high-severity vulnerabilities")
        
        # Supply chain risks
        supply_chain_risks = [v for v in vulnerabilities if v.risk_type == DependencyRisk.MALICIOUS_PACKAGE]
        if supply_chain_risks:
            recommendations.append("Review suspicious packages for supply chain security")
        
        # General recommendations
        recommendations.extend([
            "Implement automated dependency scanning in CI/CD",
            "Enable automated security updates where possible", 
            "Regular dependency audits and updates",
            "Use dependency pinning and lock files",
            "Monitor security advisories for used packages"
        ])
        
        return recommendations[:6]


# Integration function
def create_dependency_scanner():
    """Factory function to create dependency scanner"""
    return DependencyScanner()


if __name__ == "__main__":
    # Test the dependency scanner
    scanner = DependencyScanner()
    
    test_requirements = """
requests==2.25.1
flask==1.1.1
django==2.2.0
numpy==1.19.0
urllib3==1.26.0
"""
    
    result = scanner.scan_dependencies(test_requirements, "requirements.txt")
    print(json.dumps(result, indent=2, default=str))