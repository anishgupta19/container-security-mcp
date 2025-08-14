# Container AI - MCP Server
## Preview: VS Code MCP Integration & Security Scan

Below is a screenshot showing the `.vscode/mcp.json` configuration and the security scan results in VS Code:

![VS Code MCP & Security Scan Preview](https://user-images.githubusercontent.com/your-screenshot-path/vscode-mcp-security-scan.png)

**Highlights:**
- MCP server configured in `.vscode/mcp.json`
- Security scan results for multiple Dockerfiles
- Vulnerability details and recommended fixes

Docker security scanner with automated vulnerability patching via Trivy + Copacetic.
# Container AI - MCP Server

Docker security scanner with automated vulnerability patching via Trivy + Copacetic.

## Quick Start

```bash
# Install dependencies
brew install docker trivy
npm install -g @copacetic/cli

# Install Python deps & run
pip install -r requirements.txt
python3 server.py
```

Server runs on: `http://localhost:8000/mcp`

## VS Code Setup (Local HTTPS MCP)

To use this MCP server with VS Code Copilot on another repository:

1. **Start the server** (in this repo):
   ```bash
   cd /path/to/container-ai
   python3 server.py
   ```

2. **Add MCP configuration** to your target repo's `.vscode/mcp.json`:
   ```json
   {
     "servers": {
       "container-ai": {
         "url": "http://127.0.0.1:8000/mcp",
         "type": "http"
       }
     },
     "inputs": []
   }
   ```

3. **Restart VS Code** or reload the window

4. **Use with Copilot**:
   - Ask: "Scan this repo for Docker vulnerabilities"
   - Or: "Check Docker security and apply patches"

## Tool: `scan_dockerfiles_security`

**Parameters:**
- `repo_path` (required): Repository path
- `severity_filter` (optional): `["CRITICAL", "HIGH"]`
- `apply_patches` (optional): `true` to auto-fix vulnerabilities
- `update_dockerfile` (optional): `true` to update Dockerfile with security fixes

**Example:**
```json
{
  "name": "scan_dockerfiles_security",
  "arguments": {
    "repo_path": "/path/to/repo",
    "apply_patches": true,
    "update_dockerfile": true
  }
}
```

**Output:**
```json
{
  "dockerfiles_found": 1,
  "scan_results": [{
    "dockerfile": "Dockerfile",
    "vulnerabilities": {
      "total": 169,
      "severity_breakdown": {"CRITICAL": 2, "HIGH": 17, "MEDIUM": 54},
      "patching_results": {
        "status": "applied",
        "original_vulnerabilities": 169,
        "remaining_vulnerabilities": 134,
        "fixed_count": 35,
        "packages_validated": 8
      },
      "after_patching": {
        "total": 134,
        "severity_breakdown": {"CRITICAL": 0, "HIGH": 12, "MEDIUM": 48}
      },
      "dockerfile_updates": {
        "status": "updated",
        "changes": ["Added apt security updates for Ubuntu/Debian base"],
        "backup_created": "/path/to/repo/Dockerfile.backup",
        "vulnerabilities_addressed": 169,
        "severity_breakdown": {"CRITICAL": 2, "HIGH": 17, "MEDIUM": 54}
      }
    }
  }]
}
```

## What It Does

1. **Finds** Dockerfiles in repo
2. **Builds** Docker images  
3. **Scans** with Trivy
4. **Patches** vulnerabilities (optional)
5. **Re-scans** to verify fixes
6. **Reports** before/after results

That's it! 🚀

## How Container Patching Works

When you use `apply_patches: true`, here's what happens behind the scenes:

### 1. **Image Build & Initial Scan**
```bash
docker build -t mcp-scan-{hash} -f Dockerfile .
trivy image --format json mcp-scan-{hash}
```

### 2. **Copacetic Patching Process**
- Copa analyzes the Trivy vulnerability report
- Downloads security patches for vulnerable packages  
- Creates a **NEW Docker image** with patches applied
- Tags it as `mcp-scan-{hash}:patched`

### 3. **Verification Scan**
```bash
trivy image --format json mcp-scan-{hash}:patched
```

### ⚠️ **Important Notes**
- **Your Dockerfile is NOT modified** by default - source code stays unchanged
- Patching happens at the **image layer level**
- Both images are cleaned up after analysis
- This is a **security assessment tool**, not a permanent fix

### 🔧 **Auto-Update Dockerfile** (NEW!)

Set `update_dockerfile: true` to automatically fix your Dockerfile:

```json
{
  "name": "scan_dockerfiles_security", 
  "arguments": {
    "repo_path": "/path/to/repo",
    "apply_patches": true,
    "update_dockerfile": true
  }
}
```

**What happens:**
- ✅ Scans for vulnerabilities
- ✅ Tests patches with Copa  
- ✅ Updates your Dockerfile with security fixes
- ✅ Creates `Dockerfile.backup` 
- ✅ Ready to commit and deploy!

**Supported base images:**
- Ubuntu/Debian: Adds `apt-get update && apt-get upgrade -y`
- Alpine: Adds `apk update && apk upgrade`  
- CentOS/RHEL/Fedora/Rocky/AlmaLinux: Adds `yum update -y`
- Amazon Linux: Adds `yum update -y`
- SUSE/openSUSE: Adds `zypper refresh && zypper update -y`

### 🏗️ **For Production Use**
To use patched images in production:
1. Integrate Copa into your CI/CD pipeline
2. Save patched images: `docker save mcp-scan-{hash}:patched`
3. Update Dockerfiles manually with security fixes
