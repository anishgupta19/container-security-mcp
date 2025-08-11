# Container AI - MCP Server

A Model Context Protocol (MCP) server that identifies, builds, and scans Dockerfiles for security vulnerabilities using Trivy.

## Overview

This ultra-minimal MCP server provides comprehensive Docker security analysis:

1. **Identifies** all Dockerfiles in a repository
2. **Builds** Docker images from each Dockerfile  
3. **Scans** images with Trivy for vulnerabilities
4. **Analyzes** vulnerabilities by severity and dependency type (OS vs Application)

## File Structure

```
mcp-docker/
├── server.py           # Complete MCP server implementation (single file)
├── requirements.txt    # Minimal dependencies
├── README.md          # This documentation
└── .gitignore         # Git ignore rules
```

**Total: 3 core files** - Ultra-minimal implementation!

## Prerequisites

Install required system dependencies:

```bash
# Install Docker (if not installed)
brew install docker

# Install Trivy vulnerability scanner
brew install trivy

# Verify installations
docker --version
trivy --version
```

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Running the Server

The server uses HTTP Streamable transport:

```bash
python server.py
```

Server will start on `http://localhost:8000/mcp`

### Tool Available

#### `scan_dockerfiles_security`

Performs complete security analysis of Dockerfiles in a repository.

**Parameters:**
- `repo_path` (string, required): Path to the repository to scan
- `severity_filter` (array, optional): Filter by severity levels (e.g., `["CRITICAL", "HIGH"]`)

**Returns:**
Comprehensive vulnerability analysis with:
- Total vulnerabilities found
- Breakdown by severity (CRITICAL, HIGH, MEDIUM, LOW)
- Categorization by OS packages vs Application dependencies
- Top critical vulnerabilities with details

**Example Usage:**
```json
{
  "name": "scan_dockerfiles_security",
  "arguments": {
    "repo_path": "/path/to/your/repository",
    "severity_filter": ["CRITICAL", "HIGH"]
  }
}
```

**Example Output:**
```json
{
  "dockerfiles_found": 2,
  "scan_results": [
    {
      "dockerfile": "Dockerfile",
      "image_tag": "mcp-scan-123456",
      "build_status": "success",
      "vulnerabilities": {
        "total": 15,
        "severity_breakdown": {
          "CRITICAL": 2,
          "HIGH": 5,
          "MEDIUM": 8,
          "LOW": 0
        },
        "by_type": {
          "os_packages": {
            "count": 10,
            "packages": ["openssl", "curl", "bash"]
          },
          "application_deps": {
            "count": 5,
            "packages": ["npm:lodash", "pip:requests"]
          }
        },
        "top_critical": [
          {
            "vulnerability_id": "CVE-2024-1234",
            "package": "openssl",
            "severity": "CRITICAL",
            "description": "Remote code execution vulnerability...",
            "fixed_version": "1.1.1w"
          }
        ]
      }
    }
  ]
}
```

## Features

- **Complete Pipeline**: Find → Build → Scan → Analyze in one tool
- **Trivy Integration**: Industry-standard vulnerability scanner
- **Smart Categorization**: OS packages vs Application dependencies
- **Severity Filtering**: Focus on critical/high severity issues
- **Error Handling**: Graceful failure handling with informative messages
- **Automatic Cleanup**: Removes built images after scanning
- **Timeout Protection**: Prevents hanging builds/scans

## Client Connection Example

```python
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async with streamablehttp_client("http://localhost:8000/mcp") as (read, write, _):
    async with ClientSession(read, write) as session:
        await session.initialize()
        
        result = await session.call_tool("scan_dockerfiles_security", {
            "repo_path": "/path/to/repository",
            "severity_filter": ["CRITICAL", "HIGH"]
        })
        
        print(f"Found {result.content[0].text}")
```

## Requirements

- Python 3.8+
- MCP Python SDK
- Docker (system requirement)
- Trivy (system requirement)
