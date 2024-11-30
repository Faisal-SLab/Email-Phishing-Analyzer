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
## Clone the repository:
   ```bash
   git clone https://github.com/yourusername/email-phishing-analyzer.git
   cd email-phishing-analyzer
  ```
## Install dependencies:
   Install requirements
   ```bash
   pip install -r requirements.txt
```
## Set your API keys:
```bash
Replace your-virustotal-api-key and your-abuseipdb-api-key in the script with your respective API keys.
```
## Usage
Run the script:

```bash
python email_analyzer.py
```
Provide the path to the .eml file you want to analyze.

Choose whether to save the results as JSON or view them directly in the CLI.

Output
The script provides:

Email metadata (From, To, Subject, etc.)
Authentication results (SPF, DKIM, DMARC)
IP and domain reputation analysis
Extracted URLs and VirusTotal links
Suspicious keywords detected
A phishing score

## Example
Here’s an example output:
```bash
{
    "Email Information": {
        "From": "example@example.com",
        "To": "user@example.com",
        "Subject": "Urgent: Action Required",
        "Date": "2024-01-01 12:00:00",
        "Authentication-Results": "spf=pass dkim=fail dmarc=pass"
    },
    ...
}
```

Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

Disclaimer
This tool is intended for educational and research purposes only. Always respect privacy laws and obtain proper consent when analyzing email data.
