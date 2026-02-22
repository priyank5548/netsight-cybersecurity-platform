# Quick Start Guide - File Analysis Web Interface

## 🚀 Getting Started in 3 Steps

### 1. Install Dependencies
```bash
cd "e:\3 Day Project\My Project\final_project"
pip install -r requirements.txt
```

### 2. Start the Server
```bash
python app.py
```

### 3. Open in Browser
Navigate to: **http://127.0.0.1:5000/file-analysis**

---

## 📝 How to Analyze a File

1. **Click** "Choose File" button
2. **Select** the file you want to analyze
3. **Click** "🔍 Analyze File" button
4. **Wait** for analysis to complete (usually 5-30 seconds)
5. **Review** the comprehensive results displayed below

---

## 🎨 Understanding the Results

### Color Codes
- 🟢 **Green Text** = Safe/Normal
- 🟡 **Yellow Text** = Warning/Attention Needed
- 🔴 **Red Text** = Suspicious/Potential Threat

### Sections Explained

**📋 File Identification**
- Basic file info, hashes, and format detection

**🎯 Threat Attribution**  
- Checks against known malware databases

**🔬 Windows PE Analysis**  
- Deep analysis of Windows executables (EXE/DLL)

**📏 Size Analysis**
- Detects file packing/compression

**ℹ️ Additional Information**
- Entry points, imports, and executable sections

**📦 Embedded Files**
- Finds hidden files within the analyzed file

**🔍 Content Scanning**
- Searches for IPs, URLs, emails, suspicious commands

**🎯 YARA Rules**
- Advanced pattern matching for malware signatures

---

## ⚠️ Important Notes

- **Maximum file size**: 50MB
- **Best for**: Windows executables (EXE, DLL), PDFs, Office docs
- **YARA rules**: Place custom rules in `file_analysis/yara_rules/`
- **File storage**: Uploaded files are saved in `uploads/` directory

---

## 🐛 Troubleshooting

**"Module not found" error**
```bash
pip install pefile puremagic oletools yara-python
```

**"Port already in use"**
- Stop other Flask apps or change port in app.py

**"Permission denied" when uploading**
- Create `uploads/` folder manually
- Check folder permissions

---

## 🔒 Security Warning

⚠️ **Analyze files in a safe environment!**
- Use a virtual machine for unknown files
- Never execute analyzed files on production systems
- This tool is for analysis only, not prevention

---

## 📚 Need More Help?

- See `USAGE.md` for detailed documentation
- See `IMPLEMENTATION_SUMMARY.md` for technical details
- Check `file_analysis/file_analysis.py` for CLI version

---

**Status**: ✅ Ready to use!  
**Access**: http://127.0.0.1:5000/file-analysis
