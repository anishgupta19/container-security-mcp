#!/usr/bin/env python3
"""
MCP Server for Container AI - Docker security scanning.
Identifies, builds, and scans Dockerfiles with Trivy in a single file.
"""

import os
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Any

from mcp.server.fastmcp import FastMCP

# Create the MCP server with FastMCP
mcp = FastMCP("container-ai")


@mcp.tool()
def scan_dockerfiles_security(repo_path: str, severity_filter: List[str] = None) -> Dict[str, Any]:
    """
    Complete Docker security analysis in one tool:
    1. Find all Dockerfiles
    2. Build Docker images  
    3. Scan with Trivy
    4. Analyze vulnerabilities by type and severity
    
    Args:
        repo_path: Path to the repository to scan
        severity_filter: Optional list of severities to include (e.g., ["CRITICAL", "HIGH"])
        
    Returns:
        Dict containing scan results with vulnerability analysis
    """
    
    # PHASE 1: Find Dockerfiles (inline)
    dockerfiles = []
    try:
        for file_path in Path(repo_path).rglob("*"):
            if file_path.is_file():
                name = file_path.name.lower()
                if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
                    dockerfiles.append(str(file_path))
    except (PermissionError, OSError) as e:
        return {"error": f"Cannot access repository: {str(e)}"}
    
    if not dockerfiles:
        return {"dockerfiles_found": 0, "message": "No Dockerfiles found"}
    
    results = {"dockerfiles_found": len(dockerfiles), "scan_results": []}
    
    # Check if Docker and Trivy are available
    if not _check_dependencies():
        return {"error": "Docker or Trivy not available. Please install both tools."}
    
    for dockerfile in dockerfiles:
        # PHASE 2: Build image (inline subprocess)
        image_tag = f"mcp-scan-{abs(hash(dockerfile))}"
        dockerfile_path = Path(dockerfile)
        build_context = dockerfile_path.parent
        
        build_cmd = ["docker", "build", "-t", image_tag, "-f", str(dockerfile_path), str(build_context)]
        
        try:
            # Build the Docker image
            build_result = subprocess.run(build_cmd, check=True, capture_output=True, text=True, timeout=300)
            
            # PHASE 3: Trivy scan (inline subprocess)
            scan_cmd = ["trivy", "image", "--format", "json", "--quiet", image_tag]
            scan_result = subprocess.run(scan_cmd, capture_output=True, text=True, check=True, timeout=120)
            
            # PHASE 4: Parse and analyze (inline)
            if scan_result.stdout:
                trivy_data = json.loads(scan_result.stdout)
                analysis = _analyze_vulnerabilities(trivy_data, severity_filter)
            else:
                analysis = {"total": 0, "message": "No vulnerabilities found or scan failed"}
            
            results["scan_results"].append({
                "dockerfile": str(dockerfile_path.relative_to(repo_path)),
                "image_tag": image_tag,
                "build_status": "success",
                "vulnerabilities": analysis
            })
            
            # Cleanup image
            subprocess.run(["docker", "rmi", image_tag], capture_output=True)
            
        except subprocess.TimeoutExpired:
            results["scan_results"].append({
                "dockerfile": str(dockerfile_path.relative_to(repo_path)),
                "error": "Build or scan timeout"
            })
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr if e.stderr else str(e)
            results["scan_results"].append({
                "dockerfile": str(dockerfile_path.relative_to(repo_path)),
                "error": f"Build/scan failed: {error_msg[:200]}"
            })
        except json.JSONDecodeError:
            results["scan_results"].append({
                "dockerfile": str(dockerfile_path.relative_to(repo_path)),
                "error": "Failed to parse Trivy output"
            })
    
    return results


def _check_dependencies() -> bool:
    """Check if Docker and Trivy are available"""
    try:
        subprocess.run(["docker", "--version"], capture_output=True, check=True)
        subprocess.run(["trivy", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _analyze_vulnerabilities(trivy_data: Dict, severity_filter: List[str] = None) -> Dict[str, Any]:
    """Inline vulnerability analysis - no separate file needed"""
    total = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    os_vulns = []
    app_vulns = []
    top_critical = []
    
    for result in trivy_data.get("Results", []):
        result_type = result.get("Type", "").lower()
        
        for vuln in result.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "UNKNOWN")
            
            # Apply severity filter if provided
            if severity_filter and severity not in severity_filter:
                continue
                
            total += 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Categorize by type (OS vs Application dependencies)
            pkg_name = vuln.get("PkgName", "unknown")
            if result_type in ["os", "ubuntu", "alpine", "debian", "centos", "rhel"]:
                os_vulns.append(pkg_name)
            else:
                app_vulns.append(pkg_name)
            
            # Collect critical vulnerabilities for top issues
            if severity == "CRITICAL" and len(top_critical) < 5:
                top_critical.append({
                    "vulnerability_id": vuln.get("VulnerabilityID", "N/A"),
                    "package": pkg_name,
                    "severity": severity,
                    "description": vuln.get("Description", "")[:100] + "..." if len(vuln.get("Description", "")) > 100 else vuln.get("Description", ""),
                    "fixed_version": vuln.get("FixedVersion", "Not available")
                })
    
    return {
        "total": total,
        "severity_breakdown": severity_counts,
        "by_type": {
            "os_packages": {
                "count": len(os_vulns), 
                "packages": list(set(os_vulns))[:10]  # Show max 10 unique packages
            },
            "application_deps": {
                "count": len(app_vulns), 
                "packages": list(set(app_vulns))[:10]  # Show max 10 unique packages
            }
        },
        "top_critical": top_critical
    }


if __name__ == "__main__":
    # Run the server with Streamable HTTP transport
    mcp.run(transport="streamable-http")
