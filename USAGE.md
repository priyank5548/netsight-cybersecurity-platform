# File Analysis Web Interface - Usage Guide

## Overview
The file analysis feature allows you to upload any file and perform comprehensive malware analysis using the integrated `file_analysis.py` engine.

## Features Implemented

### 1. File Upload
- Upload any file type through the web interface
- Maximum file size: 50MB
- Files are temporarily stored in the `uploads/` directory

### 2. Analysis Capabilities
The analyzer performs the following checks:

#### ✅ File Identification
- MD5 and SHA256 hash calculation
- File format detection using magic bytes
- Extension spoofing detection
- Entropy analysis (detects encryption/packing)

#### ✅ Threat Attribution
- Import hash (imphash) calculation for PE files
- Comparison against known malware database
- Malware family identification

#### ✅ Windows PE Deep Analysis
- Digital signature verification
- Packer detection (UPX, etc.)
- Compilation timestamp analysis
- Timestomping detection
- Dangerous API identification (VirtualAlloc, WriteProcessMemory, etc.)

#### ✅ Size Analysis
- Raw vs Virtual size comparison
- Ratio calculation for packing detection

#### ✅ Additional Information
- RWX (Read-Write-Execute) section detection
- Entry point section identification
- Import count analysis
- Packed loader detection

#### ✅ Embedded Files Detection
- ZIP archives in executables
- Hidden PE files
- Embedded PDFs
- ELF binaries

#### ✅ Content Scanning
- IPv4 address extraction
- Email address detection
- URL discovery
- Registry key identification
- Suspicious command detection (cmd.exe, powershell, wget, curl)

#### ✅ YARA Rules Scanning
- Automatic compilation of YARA rules
- Pattern matching against malware signatures
- Detailed match reporting

## Installation

1. Install required dependencies:
```bash
pip install -r requirements.txt
```

2. Ensure YARA rules are in place:
```
final_project/
  file_analysis/
    yara_rules/
      [your .yar or .yara files]
```

3. Run the application:
```bash
python app.py
```

4. Access the web interface:
```
http://127.0.0.1:5000/file-analysis
```

## Usage Steps

1. **Navigate to File Analysis**: Click on the "File Analysis" link or go to `/file-analysis`

2. **Select File**: Click "Choose File" and select the file you want to analyze

3. **Upload and Analyze**: Click the "🔍 Analyze File" button

4. **Review Results**: The analysis results will be displayed on the same page with:
   - Color-coded indicators (Green = Safe, Yellow = Warning, Red = Suspicious)
   - Detailed sections for each analysis component
   - Clear alerts for critical findings

## Color Coding

- **🟢 Green**: Safe/Normal behavior
- **🟡 Yellow**: Warning - requires attention
- **🔴 Red**: Suspicious - potential threat detected

## Important Notes

- Files are saved to the `uploads/` directory during analysis
- To automatically delete files after analysis, uncomment the cleanup line in `app.py`:
  ```python
  os.remove(filepath)
  ```
- YARA scanning requires valid YARA rule files in `file_analysis/yara_rules/`
- Some features (like PE analysis) only work on Windows executable files

## Troubleshooting

### Missing Dependencies
If you see import errors, install the missing package:
```bash
pip install pefile puremagic oletools yara-python
```

### YARA Errors
- Ensure YARA rules have correct syntax
- Invalid rules are automatically skipped with a message

### Upload Errors
- Check file size (must be < 50MB)
- Ensure `uploads/` directory exists and is writable

## Security Considerations

⚠️ **WARNING**: This tool is designed for malware analysis in a controlled environment.

- Always analyze files in an isolated/sandboxed environment
- Do not execute analyzed files on production systems
- Be cautious when handling potentially malicious files
- Use a dedicated analysis VM when possible

## Integration with CLI

The web interface uses a modified version of `file_analysis.py` called `web_analyzer.py` that:
- Returns structured data instead of printing to console
- Captures all analysis results in a dictionary
- Removes colorama formatting (replaced with HTML styling)
- Handles errors gracefully for web display

The original CLI tool (`file_analysis.py`) remains unchanged and can still be used independently.
