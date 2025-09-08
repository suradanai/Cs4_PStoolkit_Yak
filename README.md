# 🔍 Cs4 PStoolkit Yak

**Advanced Pattern Search & Replace Tool for Firmware Files**

A powerful, standalone pattern search and replacement tool specifically designed for firmware files. Features beautiful UI, advanced safety mechanisms, and comprehensive firmware integrity checking.

## ✨ Features

### 🎯 **Advanced Pattern Search**
- **Text Patterns**: Search and replace in configuration files
- **Binary Patterns**: Safe hex pattern search with equal-length replacement  
- **Config Patterns**: Specialized patterns for common firmware settings
- **Real-time Preview**: See changes before applying

### 🛡️ **Safety First**
- **Binary File Detection**: Automatically detects binary vs text files
- **Size Preservation**: Maintains file size for binary files
- **Automatic Backup**: Creates timestamped backups before any modification
- **Hash Verification**: SHA256 integrity checking
- **Signature Preservation**: Protects firmware signatures

### 🎨 **Beautiful Interface**
- **Modern UI Design**: Professional, intuitive interface
- **Color-coded Patterns**: Different colors for different pattern types
- **Tabbed Interface**: Organized pattern categories
- **Full-screen Results**: Comprehensive search results display
- **Custom Styling**: Beautiful gradients and professional appearance

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- PySide6 for GUI components

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/YOUR_USERNAME/pattern_search_toolkit.git
cd pattern_search_toolkit
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run the application:**
```bash
python app.py
```

## 📖 Usage

### Basic Pattern Search
1. Launch the application: `python app.py`
2. Select your firmware file using "Browse" button
3. Choose pattern type (Text/Binary/Config)
4. Click preset buttons or enter custom patterns
5. Click "🔍 Search" to find matches
6. Review results and click "💾 Save Changes" if satisfied

## 🎨 Pattern Types

### 📝 Text Patterns
Perfect for configuration files:
- **bootdelay=0** → **bootdelay=3**
- **console=ttyS0** → **console=ttyS1**
- **root=/dev/mtdblock2** → **root=/dev/mtdblock3**

### 🔢 Binary Patterns  
For firmware binary modifications:
- **Hex Pattern Search**: Find and replace hex sequences
- **Equal-length replacement**: Maintains binary file integrity
- **Automatic padding**: Ensures proper alignment

### ⚙️ Config Patterns
Common firmware configurations:
- Boot delay modifications
- Console redirection
- Root filesystem changes
- Network interface settings

## 🛡️ Safety Features

### Automatic Backup System
- Creates `.backup.TIMESTAMP` files before any modification
- Preserves original file permissions and metadata
- Easy restoration with built-in tools

### Binary File Protection
- Detects binary files automatically
- Enforces equal-length replacements
- Prevents accidental corruption
- Maintains file signatures

## 📄 License

This project is licensed under the MIT License.

---

**Made with ❤️ for the firmware development community**
# Cs4_PStoolkit_Yak
