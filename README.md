# Snaffler 

![A dictionary definition of "snaffle".](./snaffler.png)

## What is it for? 

Snaffler is a tool for **pentesters** and **red teamers** to help find delicious candy needles (creds mostly, but it's flexible) in a bunch of horrible boring haystacks (a massive Windows/AD environment).

It might also be useful for other people doing other stuff, but it is explicitly NOT meant to be an "audit" tool.

---

## 🚀 What's New in This Version?

This version includes several critical improvements over the original Snaffler:

### 🔧 **Enhanced Task Completion Detection**
- **Better reliability**: Fixed issues where Snaffler would exit prematurely before completing all file scans
- **Real-time monitoring**: Added debug output showing task queue status (queued/running/completed)
- **Polling mechanism**: Replaced problematic timer-based completion with robust polling loop
- **Accurate counters**: Task schedulers now properly track completed work across all three phases (share discovery, tree walking, file scanning)

### 📈 **Excel Report Generation** 
- **New `-t auto` flag**: Automatically generates Excel reports (.xlsx) with findings
- **Better analysis**: Structured output perfect for reporting and sharing results with teams
- **LogType.Auto**: New log type option specifically for Excel export functionality

### 📂 **External Rules Loading**
- **Flexible rules**: Load custom TOML rules from external `SnaffRules/DefaultRules/` directory
- **No recompilation**: Modify detection rules without rebuilding the entire project
- **User-specified paths**: Use `-p <path>` to load rules from any directory
- **Better debugging**: Detailed console output showing which rules are loaded and from where

### 🐛 **Stability Improvements**
- Enhanced error handling in file and tree scanning operations
- Better task scheduler queue management
- More informative debug messages throughout the scanning process
- Fixed completion detection logic preventing premature exits

### 🎨 **Improved User Experience**
- More verbose logging options showing scan progress
- Clear indicators when tasks start and complete
- Total file count displayed at completion
- Better feedback during long-running operations

---

## 💡 Quick Start

**TL;DR** - Don't want to read? Just run this:

```bash
snaffler.exe -s -o snaffler.log
```

But seriously, read the options below for better results! 🙃

---

## 📖 What Does It Do?

**Broadly speaking** - Snaffler:

1. 🖥️ Gets a list of Windows computers from Active Directory
2. 🌐 Spreads out to discover accessible file shares on those computers
3. 📁 Enumerates ALL files in readable shares
4. 🤖 Uses **intelligent pattern matching** (regex rules + heuristics) to identify interesting files
5. 📊 Outputs results in multiple formats including plain text, JSON, or Excel

> **Note**: Despite what we'd love to claim, it doesn't use actual ML - just really good pattern matching with lots of `if` statements and regexen. But it works remarkably well! 😄

---

## 🎨 What Does It Look Like?

<p align="center">
  <img src="./snaffler_screenshot.png">
</p>

---

## 🔑 How Do I Use It?

### ⚠️ Important Note

If you "literally just run the EXE on a domain joined machine in the context of a domain user" without any flags, it will basically do nothing. This is intentional (our little prank 🎭 on people who skip README files).

**You MUST add the correct flags** to enable scanning and output.

---

## 🎛️ Key Command-Line Options

### **Essential Flags** ⭐

| Flag | Description |
|------|-------------|
| `-o <file>` | 📝 Output results to a file (e.g., `-o C:\results\audit.log`) |
| `-s` | 🖥️ Output results to stdout in real-time |
| `-t <type>` | 📊 Log type: `plain`, `json`, or **`auto`** (Excel export - NEW!) |

### **Verbosity Control** 🔊

| Flag | Description |
|------|-------------|
| `-v <level>` | Set verbosity: `Trace` (most verbose), `Debug`, `Info` (default), `Data` (results only) |

### **File Collection** 📥

| Flag | Description |
|------|-------------|
| `-m <dir>` | 📂 Auto-copy found files to specified directory |
| `-l <bytes>` | 📏 Max file size to copy (default: ~10MB) |

### **Scope Control** 🎯

| Flag | Description |
|------|-------------|
| `-i <path>` | 📍 Disable discovery, scan specific directory only |
| `-n <hosts>` | 🖥️ Disable computer discovery, scan specific hosts (comma-separated or file path) |
| `-d <domain>` | 🌐 Specify domain to search |
| `-c <DC>` | 🎮 Domain controller to query |
| `-f` | 🌲 Use DFS only (stealthier!) |
| `-a` | 📋 List shares only, skip file enumeration |

### **Advanced Options** ⚙️

| Flag | Description |
|------|-------------|
| `-b <0-3>` | 🎚️ Boring level - skip less interesting findings (0=find everything, 3=only critical) |
| `-u` | 👤 Pull interesting usernames from AD and search for them |
| `-r <bytes>` | 🔍 Max file size to search inside for strings (default: 500KB) |
| `-j <bytes>` | 📝 Context bytes around found strings (e.g., `-j 200`) |
| `-z <path>` | ⚙️ Path to config file (use `-z generate` to create template) |
| `-p <path>` | 📚 Load custom rules from directory |
| `-x <num>` | 🧵 Max threads (don't go below 4) |
| `-y` | 📊 TSV-formatted output |

---

## 📊 Understanding the Output

Here's an annotated example of a log entry:

<p align="center">
  <img src="./log_key.png" alt="Log Key">
</p>

**Reading left to right:**

1. ⏰ **Timestamp** - When the file was found
2. 🚨 **Triage Level** - Color-coded importance (Red = very interesting, Yellow = somewhat interesting, etc.)
3. 📋 **Rule Name** - Which detection rule matched
4. 🔒 **Access Level** - Your permissions (R=Read, W=Write, etc.)
5. 🎯 **Matched Pattern** - The exact regex that triggered
6. 📦 **File Size** - Size in bytes/KB/MB
7. 📅 **Last Modified** - When the file was last changed
8. 📁 **File Path** - Full UNC path to the file

### 🎨 Triage Levels

- 🔴 **Red** - Highly sensitive (credentials, private keys, etc.)
- 🟡 **Yellow** - Interesting (configs, database files)
- 🟢 **Green** - Potentially useful (scripts, documentation)
- ⚪ **Black** - Low priority but logged

---

## 🆕 New Features Usage Examples

### Excel Report Generation

```bash
# Generate Excel report with all findings
snaffler.exe -s -t auto -o results.log

# Excel file will be created automatically with structured data
# Perfect for team collaboration and reporting!
```

### Custom Rules Loading

```bash
# Load rules from custom directory
snaffler.exe -s -o audit.log -p "C:\MyCustomRules"

# Or place rules in SnaffRules/DefaultRules/ next to the executable
# Snaffler will auto-detect and load them!
```

### Targeted Auditing with Better Completion

```bash
# Audit specific hosts with verbose output
snaffler.exe -s -o results.log -n "DC01,FILESERVER01,BACKUP01" -v Debug

# Improved task tracking ensures all files are scanned
# before exiting - no more premature termination! 🎉
```

---

## 🔧 Building from Source

### Prerequisites

- .NET Framework (for Snaffler.sln) or .NET Core (for UltraSnaffler.sln)
- Visual Studio 2019 or later

### Build Steps

```bash
# Clone the repository
git clone https://github.com/yourusername/Snaffler.git
cd Snaffler

# Restore NuGet packages
dotnet restore

# Build the project
dotnet build -c Release

# Or use Visual Studio
# Open Snaffler.sln or UltraSnaffler.sln and build
```

---

## 📝 Configuration Files

Generate a sample config with all options:

```bash
snaffler.exe -z generate
```

This creates `default.toml` showing all configurable options including:
- Custom classification rules
- File extension filters
- Content regex patterns
- Output formatting
- Thread pool settings

---

## 🎯 Common Use Cases

### 🔍 Quick Domain-Wide Scan
```bash
snaffler.exe -s -d contoso.local -o scan_results.log -v Info
```

### 🎯 Targeted File Server Audit
```bash
snaffler.exe -s -n "FILESERVER01" -o fileserver_audit.log -m C:\findings -l 50000000
```

### 📊 Generate Excel Report for Management
```bash
snaffler.exe -s -t auto -d contoso.local -o executive_report.log -b 2
```

### 🥷 Stealthy DFS-Only Enumeration
```bash
snaffler.exe -s -f -d contoso.local -o stealthy_scan.log
```

### 🔎 Deep Dive on Specific Share
```bash
snaffler.exe -s -i "\\FILESERVER01\Finance" -o finance_deep_dive.log -r 5000000
```

---

## ⚠️ Legal Disclaimer

**Snaffler** is intended for authorized security testing and research purposes only. 

- ✅ Use on networks you own or have explicit permission to test
- ❌ Do NOT use on systems without authorization
- 🎓 For educational and legitimate security assessment only

**The authors assume no liability for misuse of this tool.**

---

## 📜 License

This project is licensed under the Apache License 2.0 - see the Licence for details.

---

<p align="center">
  <sub>🔴🟡🟢 Happy Hunting! 🔍</sub>
</p>

