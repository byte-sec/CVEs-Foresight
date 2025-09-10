# CVE Foresight

An AI-powered CVE dashboard that provides foresight by integrating NVD data with the CISA KEV catalog, helping you prioritize threats that are actively exploited in the wild.

## Features

### Core Capabilities
- **Real-time CVE Monitoring** - Fetch and sync vulnerability data from the National Vulnerability Database (NVD)
- **AI-Powered Analysis** - Leverage Google's Gemini AI for automated vulnerability risk assessment and exploit payload generation
- **Threat Intelligence Integration** - Direct integration with CISA's Known Exploited Vulnerabilities (KEV) catalog
- **Advanced Search & Filtering** - Comprehensive search with multiple filter options for targeted threat hunting
- **Interactive Dashboard** - Visual analytics showing severity distribution and top weakness patterns

### Professional Security Features
- **Active Threat Prioritization** - Focus on vulnerabilities that are actively being exploited in the wild
- **CWE Mapping** - Complete Common Weakness Enumeration database integration for weakness analysis
- **Memory-Optimized Performance** - LRU caching and automatic cleanup for handling large datasets
- **Thread-Safe Operations** - Robust multi-threaded architecture for concurrent data processing
- **Encrypted Configuration** - Secure API key storage with automatic encryption

## Requirements

- **Python 3.8+**
- **NVD API Key** (Required) - [Get your free API key here](https://nvd.nist.gov/developers/request-an-api-key)
- **Google Gemini API Key** (Optional) - Required for AI analysis features

## Installation

1. **Clone the repository:**
```bash
git clone https://github.com/byte-sec/CVEs-Foresight.git
cd CVEs-Foresight
```

2. **Create virtual environment:**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Run the application:**
```bash
python main.py
```

## Quick Start

1. **First Launch Setup:**
   - The application will prompt for your NVD API key (required)
   - Optionally add your Gemini API key for AI features
   - The CWE database will be automatically set up on first run

2. **Sync CVE Data:**
   - Click "Start Syncing" to download vulnerability data from NVD

3. **Update Threat Intelligence:**
   - Navigate to the Dashboard tab
   - Click "Update KEV Catalog" to fetch the latest actively exploited vulnerabilities
   - This data helps prioritize which vulnerabilities pose immediate threats

## Configuration

### Environment Variables (Recommended for Production)
```bash
export CVE_NVD_API_KEY="your-nvd-api-key"
export CVE_GEMINI_API_KEY="your-gemini-api-key"
```

### Configuration File
The application automatically creates an encrypted configuration file on first run. Manual configuration is stored in `config.json` (development) or `config.encrypted` (production).

## Usage

### CVE Feed Tab
- **Search & Filter:** Use keyword search or advanced filters for specific CVEs
- **AI Analysis:** Click "Analyze with AI" on any CVE for automated risk assessment
- **Export Data:** View detailed vulnerability information including CWE mappings

### Dashboard Tab
- **Active Threats:** View CVEs that are being actively exploited (CISA KEV)
- **Severity Distribution:** Overview of vulnerability severity levels in your database
- **Top Weakness Types:** Most common CWE categories affecting your environment

## API Rate Limiting

The application includes intelligent rate limiting:
- **NVD API:** 5 requests per second (with API key)
- **Response Caching:** Reduces redundant API calls by 50-80%
- **Automatic Backoff:** Handles rate limits gracefully with exponential backoff

## Architecture

```
cve-foresight/
├── backend/           # Core business logic and API handlers
├── gui/              # User interface components
├── database.py       # Thread-safe database operations
├── config_manager.py # Encrypted configuration management
├── validation.py     # Input validation and security
├── memory_manager.py # Performance optimization
├── logging_config.py # Comprehensive logging system
└── main.py          # Application entry point
```



## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request


### Logging
Comprehensive logs are stored in the `logs/` directory:
- `cve_dashboard.log` - Main application log
- `errors.log` - Error-only log for troubleshooting
- `database.log` - Database operation logs

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.



**Disclaimer:** This tool is for educational and professional cybersecurity purposes. Users are responsible for complying with all applicable laws and regulations when using vulnerability data.
