# Email Phishing Analyzer

Email Phishing Analyzer is a Python script designed to help identify potential phishing attempts by analyzing email headers, body content, and associated metadata. The script uses external APIs (VirusTotal and AbuseIPDB) to further evaluate IP addresses and URLs for suspicious activities.

## Features

- **Email Parsing**: Reads and parses `.eml` files to extract relevant information.
- **Header Analysis**: Examines SPF, DKIM, and DMARC authentication results.
- **IP Reputation Check**: Uses AbuseIPDB to check the sender's IP reputation.
- **URL Analysis**: Scans URLs found in the email body and links to VirusTotal for additional inspection.
- **Keyword Detection**: Searches for suspicious keywords grouped by categories like financial terms, personal information, urgent actions, and more.
- **Phishing Scoring**: Calculates a phishing score based on findings.
- **Output Options**: Displays results on the CLI or saves them as a JSON file.

## Installation

### Prerequisites
- Python 3.7 or higher
- API keys for:
  - [VirusTotal](https://www.virustotal.com/)
  - [AbuseIPDB](https://www.abuseipdb.com/)

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/email-phishing-analyzer.git
   cd email-phishing-analyzer
