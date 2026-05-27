# CVE Monitoring Tool

A C++ command-line CVE monitor that queries the official NVD CVE 2.0 API and enriches matching results with CISA Known Exploited Vulnerabilities (KEV) catalog data.

## Features

- Search recently published CVEs by date window
- Look up a specific CVE ID
- Filter by keyword and CVSS v3 severity
- Annotate results with CISA KEV known-exploited status
- Output human-readable text or JSON
- Optional watch mode for repeated checks
- Supports an NVD API key through `NVD_API_KEY` or `--api-key`

## APIs Used

- NVD CVE API 2.0: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- CISA KEV JSON feed: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

## Dependencies

- C++17 compiler
- CMake 3.20+
- libcurl
- nlohmann-json

With vcpkg:

```powershell
vcpkg install curl nlohmann-json
```

## Build

```powershell
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake"
cmake --build build --config Release
```

If your dependencies are installed system-wide, omit `CMAKE_TOOLCHAIN_FILE`.

## Usage

```powershell
.\build\Release\cve-monitor.exe --days 3 --severity CRITICAL
.\build\Release\cve-monitor.exe --keyword openssl --limit 10
.\build\Release\cve-monitor.exe --cve CVE-2024-3094 --json
.\build\Release\cve-monitor.exe --days 1 --watch-minutes 30
```

Optional API key:

```powershell
$env:NVD_API_KEY="your-api-key"
.\build\Release\cve-monitor.exe --days 7 --severity HIGH
```

## Portfolio Notes

This project demonstrates API integration, security data enrichment, JSON parsing, command-line interface design, error handling, and practical vulnerability-management prioritization.

## Disclaimer

This tool is for vulnerability awareness and triage. Confirm exploitability and patch guidance against vendor advisories before making production remediation decisions.
