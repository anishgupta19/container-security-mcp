#!/usr/bin/env python3
"""
Container AI MCP Server - Docker security scanning with Copacetic patching.
Single-file implementation: Trivy scanning + Copa patching + vulnerability analysis.
"""

import os
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Any
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("container-ai")


@mcp.tool()
def scan_dockerfiles_security(repo_path: str, severity_filter: List[str] = None, apply_patches: bool = False, update_dockerfile: bool = False) -> Dict[str, Any]:
    """
    Docker security scanner with optional Copacetic patching.
    
    Args:
        repo_path: Repository path to scan
        severity_filter: Optional severity filter (e.g., ["CRITICAL", "HIGH"])
        apply_patches: Whether to apply Copa patches (default: false)
        update_dockerfile: Whether to update the original Dockerfile with fixes (default: false)
        
    Returns: Scan results with vulnerability analysis and optional patching results
    """
    
    # Find all Dockerfiles
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
    
    # Check dependencies
    if not _check_dependencies():
        return {"error": "Docker or Trivy not available. Please install both tools."}
    
    copa_available = _check_copacetic()
    if apply_patches and not copa_available:
        return {"error": "Copacetic not available. Please install Copa CLI to use patching feature."}
    
    for dockerfile in dockerfiles:
        image_tag = f"mcp-scan-{abs(hash(dockerfile))}"
        dockerfile_path = Path(dockerfile)
        
        try:
            # Build image
            build_cmd = ["docker", "build", "-t", image_tag, "-f", str(dockerfile_path), str(dockerfile_path.parent)]
            subprocess.run(build_cmd, check=True, capture_output=True, text=True, timeout=300)
            
            # Scan with Trivy
            scan_cmd = ["trivy", "image", "--format", "json", "--quiet", image_tag]
            scan_result = subprocess.run(scan_cmd, capture_output=True, text=True, check=True, timeout=120)
            
            # Analyze vulnerabilities
            if scan_result.stdout:
                trivy_data = json.loads(scan_result.stdout)
                analysis = _analyze_vulnerabilities(trivy_data, severity_filter)
                
                # Apply patches if requested
                if apply_patches and copa_available:
                    analysis = _apply_patches(image_tag, trivy_data, analysis, severity_filter)
                    
                    # Update Dockerfile if requested and patches were applied
                    if update_dockerfile and analysis.get("patching_results", {}).get("status") == "applied":
                        dockerfile_updates = _update_dockerfile_with_fixes(str(dockerfile_path), analysis)
                        analysis["dockerfile_updates"] = dockerfile_updates
                
                # Update Dockerfile even without patching if requested and vulnerabilities exist
                elif update_dockerfile and analysis.get("total", 0) > 0:
                    dockerfile_updates = _update_dockerfile_with_fixes(str(dockerfile_path), analysis)
                    analysis["dockerfile_updates"] = dockerfile_updates
            else:
                analysis = {"total": 0, "message": "No vulnerabilities found or scan failed"}
            
            results["scan_results"].append({
                "dockerfile": str(dockerfile_path.relative_to(repo_path)),
                "image_tag": image_tag,
                "build_status": "success",
                "vulnerabilities": analysis
            })
            
            # Cleanup
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


def _check_copacetic() -> bool:
    """Check if Copacetic is available"""
    try:
        subprocess.run(["copa", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _apply_patches(image_tag: str, trivy_data: Dict, analysis: Dict, severity_filter: List[str]) -> Dict:
    """Apply Copa patches and update analysis"""
    patched_tag = f"{image_tag}-patched"
    expected_patched_image = f"{image_tag}:{patched_tag}"
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(trivy_data, f)
        report_path = f.name
    
    try:
        # Run Copa patch
        patch_cmd = ["copa", "patch", "--image", image_tag, "--report", report_path, "--tag", patched_tag, "--timeout", "5m"]
        patch_result = subprocess.run(patch_cmd, capture_output=True, text=True, check=True, timeout=360)
        
        # Parse Copa output
        packages_validated = patch_result.stdout.count("Validated package") if patch_result.stdout else 0
        
        # Re-scan patched image
        try:
            rescan_cmd = ["trivy", "image", "--format", "json", "--quiet", expected_patched_image]
            rescan_result = subprocess.run(rescan_cmd, capture_output=True, text=True, check=True, timeout=120)
            
            if rescan_result.stdout:
                patched_trivy_data = json.loads(rescan_result.stdout)
                patched_analysis = _analyze_vulnerabilities(patched_trivy_data, severity_filter)
                
                analysis["patching_results"] = {
                    "status": "applied",
                    "original_vulnerabilities": analysis["total"],
                    "remaining_vulnerabilities": patched_analysis["total"],
                    "fixed_count": analysis["total"] - patched_analysis["total"],
                    "packages_validated": packages_validated
                }
                analysis["after_patching"] = patched_analysis
            
            subprocess.run(["docker", "rmi", expected_patched_image], capture_output=True)
            
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            analysis["patching_results"] = {"status": "rescan_failed", "error": str(e)[:200]}
            subprocess.run(["docker", "rmi", expected_patched_image], capture_output=True)
            
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        error_msg = e.stderr if hasattr(e, 'stderr') and e.stderr else str(e)
        analysis["patching_results"] = {"status": "failed", "error": error_msg[:200]}
    finally:
        os.unlink(report_path)
    
    return analysis


def _analyze_vulnerabilities(trivy_data: Dict, severity_filter: List[str] = None) -> Dict[str, Any]:
    """Analyze Trivy scan results"""
    total = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    top_critical = []
    
    for result in trivy_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "UNKNOWN")
            
            if severity_filter and severity not in severity_filter:
                continue
                
            total += 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Collect top critical vulnerabilities
            if severity == "CRITICAL" and len(top_critical) < 3:
                top_critical.append({
                    "vulnerability_id": vuln.get("VulnerabilityID", "N/A"),
                    "package": vuln.get("PkgName", "unknown"),
                    "severity": severity,
                    "description": vuln.get("Description", "")[:100] + "..." if len(vuln.get("Description", "")) > 100 else vuln.get("Description", "")
                })
    
    return {
        "total": total,
        "severity_breakdown": severity_counts,
        "top_critical": top_critical
    }


def _update_dockerfile_with_fixes(dockerfile_path: str, analysis: Dict) -> Dict:
    """Update Dockerfile with security fixes based on patch analysis"""
    try:
        # Check if file exists and is readable
        if not Path(dockerfile_path).exists():
            return {"status": "failed", "error": "Dockerfile not found"}
        
        # Read original Dockerfile
        dockerfile_content = Path(dockerfile_path).read_text()
        if not dockerfile_content.strip():
            return {"status": "failed", "error": "Dockerfile is empty"}
            
        original_lines = dockerfile_content.splitlines()
        
        # Check if backup already exists
        backup_path = f"{dockerfile_path}.backup"
        if Path(backup_path).exists():
            backup_path = f"{dockerfile_path}.backup.{abs(hash(dockerfile_content))}"
        
        # Create backup
        Path(backup_path).write_text(dockerfile_content)
        
        changes_made = []
        updated_lines = []
        
        # Simple approach: add security update layer after FROM
        from_found = False
        security_added = False
        
        for line in original_lines:
            updated_lines.append(line)
            
            # Add security updates after the first FROM statement
            if line.strip().startswith('FROM ') and not from_found and not security_added:
                from_found = True
                base_image = line.strip().lower()
                
                # Skip if it's a multi-stage build intermediate image (FROM ... AS ...)
                if ' as ' in base_image:
                    continue
                
                # Detect base image and add appropriate security commands
                if any(distro in base_image for distro in ['ubuntu', 'debian']):
                    updated_lines.append("")
                    updated_lines.append("# Security updates applied by Container AI MCP")
                    updated_lines.append("RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*")
                    changes_made.append("Added apt security updates for Ubuntu/Debian base")
                    security_added = True
                    
                elif 'alpine' in base_image:
                    updated_lines.append("")
                    updated_lines.append("# Security updates applied by Container AI MCP")
                    updated_lines.append("RUN apk update && apk upgrade && rm -rf /var/cache/apk/*")
                    changes_made.append("Added apk security updates for Alpine base")
                    security_added = True
                    
                elif any(distro in base_image for distro in ['centos', 'rhel', 'fedora', 'rocky', 'almalinux']):
                    updated_lines.append("")
                    updated_lines.append("# Security updates applied by Container AI MCP")
                    updated_lines.append("RUN yum update -y && yum clean all")
                    changes_made.append("Added yum security updates for RHEL/CentOS/Fedora base")
                    security_added = True
                    
                elif 'amazonlinux' in base_image:
                    updated_lines.append("")
                    updated_lines.append("# Security updates applied by Container AI MCP")
                    updated_lines.append("RUN yum update -y && yum clean all")
                    changes_made.append("Added yum security updates for Amazon Linux base")
                    security_added = True
                    
                elif any(distro in base_image for distro in ['opensuse', 'suse']):
                    updated_lines.append("")
                    updated_lines.append("# Security updates applied by Container AI MCP")
                    updated_lines.append("RUN zypper refresh && zypper update -y && zypper clean -a")
                    changes_made.append("Added zypper security updates for SUSE base")
                    security_added = True
        
        if changes_made:
            # Write updated Dockerfile
            updated_content = '\n'.join(updated_lines)
            Path(dockerfile_path).write_text(updated_content)
            
            vulnerability_count = analysis.get("total", 0)
            severity_info = analysis.get("severity_breakdown", {})
            
            return {
                "status": "updated",
                "changes": changes_made,
                "backup_created": backup_path,
                "vulnerabilities_addressed": vulnerability_count,
                "severity_breakdown": severity_info
            }
        else:
            # Remove backup if no changes made
            Path(backup_path).unlink()
            return {
                "status": "no_changes",
                "reason": "Could not determine base image package manager or unsupported base image",
                "detected_base": next((line for line in original_lines if line.strip().startswith('FROM ')), "unknown")
            }
            
    except Exception as e:
        return {
            "status": "failed",
            "error": str(e)[:200]
        }


if __name__ == "__main__":
    # Run the server with Streamable HTTP transport
    mcp.run(transport="streamable-http")
