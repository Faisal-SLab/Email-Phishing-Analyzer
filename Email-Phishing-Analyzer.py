import os
import re
import requests
from email import policy
from email.parser import BytesParser
import json

# API Keys
VIRUSTOTAL_API_KEY = "your-virustotal-api-key"
ABUSEIPDB_API_KEY = "your-abuseipdb-api-key"


# Suspicious keywords grouped by category
SUSPICIOUS_KEYWORDS = {
    "financial": [
        "account", "bank", "transaction", "invoice", "payment", "credit card", 
        "debit card", "balance", "transfer", "withdrawal", "deposit", "funds", 
        "loan", "bill", "refund", "claim", "tax", "wire transfer", "earnings"
    ],
    "personal_info": [
        "password", "login", "username", "SSN", "social security", "email address", 
        "verification", "personal information", "ID number", "mother's maiden name", 
        "security question", "birthday", "driver's license", "passport number", 
        "credit report", "bank account number", "PIN", "security code"
    ],
    "urgent_action": [
        "urgent", "immediate", "action required", "respond now", "attention", "asap", 
        "verify", "act fast", "important", "critical", "failure to act", "limited time", 
        "time sensitive", "deadline", "don't miss", "last chance", "act immediately"
    ],
    "rewards_and_incentives": [
        "offer", "free", "gift", "reward", "promotion", "claim now", "redeem", 
        "winner", "prize", "congratulations", "exclusive offer", "limited time offer", 
        "exclusive access", "discount", "voucher", "bonus", "gift card", "cash prize", 
        "holiday special", "get your reward"
    ],
    "fake_brands": [
        "paypal", "apple", "google", "amazon", "microsoft", "facebook", "instagram", 
        "twitter", "netflix", "ebay", "adobe", "bank of america", "wells fargo", 
        "chase", "american express", "samsung", "t-mobile", "att", "verizon", "citi", 
        "paypal", "hsbc", "barclays", "skype", "dropbox", "linkedin", "zoom", "whatsapp"
    ],
    "tech_terms": [
        "software update", "security patch", "virus alert", "malware", "warning", 
        "trojan", "phishing attempt", "firewall", "password reset", "2FA", "login attempt", 
        "account locked", "suspicious activity", "data breach", "new device login", 
        "account compromised", "encrypted", "secure", "authenticator"
    ],
    "social_engagement": [
        "click here", "download", "open attachment", "open link", "view image", "open file", 
        "accept request", "join now", "sign up", "register", "secure your account", 
        "unlock", "click to claim", "view offer", "start now", "download now", 
        "take action", "confirm", "subscribe", "free download", "open now", "free access"
    ],
    "threats_and_intimidation": [
        "suspended account", "your account will be locked", "illegal activity", "fraud alert", 
        "unauthorized login", "immediately block", "stop using", "you have been flagged", 
        "unpaid balance", "compensation", "legal action", "court", "lawsuit", "sue", 
        "severe consequences", "non-compliance", "imminent danger", "fail to act"
    ]
}

def read_email_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        return msg
    except Exception as e:
        print(f"Error reading email file: {e}")
        return None

def extract_headers(msg):
    headers = {
        "From": msg["From"],
        "To": msg["To"],
        "Subject": msg["Subject"],
        "Date": msg["Date"],
        "Authentication-Results": msg["Authentication-Results"] or "None"
    }
    return headers

def extract_ip_and_domain_from_authentication_results(auth_results):
    """
    Extracts domain and IP address from Authentication-Results header.
    """
    ip = None
    domain = None
    # Find the sender IP address and domain in the Authentication-Results header
    ip_match = re.search(r"\(sender IP is ([\d\.]+)\)", auth_results)
    domain_match = re.search(r"smtp.mailfrom=([\w.-]+)", auth_results)
    
    if ip_match:
        ip = ip_match.group(1)
    if domain_match:
        domain = domain_match.group(1)
    
    return ip, domain

def parse_authentication_results(auth_results):
    results = {}
    spf_match = re.search(r"spf=([\w\-]+)", auth_results)
    dkim_match = re.search(r"dkim=([\w\-]+)", auth_results)
    dmarc_match = re.search(r"dmarc=([\w\-]+)", auth_results)
    
    if spf_match:
        results["SPF"] = spf_match.group(1)
    if dkim_match:
        results["DKIM"] = dkim_match.group(1)
    if dmarc_match:
        results["DMARC"] = dmarc_match.group(1)
    
    return results

def analyze_ip_with_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json().get("data", {})
        else:
            return {"error": f"Failed to fetch data, status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def analyze_urls_with_virustotal(urls):
    vt_results = {}
    for url in urls:
        hashed_url = requests.utils.quote(url.strip(), safe="")  # Ensuring the URL is encoded correctly
        vt_link = f"https://www.virustotal.com/gui/url/{hashed_url}"
        vt_results[url] = vt_link
    return vt_results

def analyze_keywords_in_body(body):
    detected = {}
    for category, keywords in SUSPICIOUS_KEYWORDS.items():
        found = []
        for keyword in keywords:
            if re.search(r"\b" + re.escape(keyword) + r"\b", body, re.IGNORECASE):
                found.append(keyword)
        if found:
            detected[category] = found
    return detected

def get_cleaned_body(msg):
    # Extract body from the email message (both HTML and plain text)
    body = msg.get_body(preferencelist=("plain", "html"))
    body_content = body.get_content() if body else "No body found"
    # Clean the HTML by removing unnecessary tags
    cleaned_body = re.sub(r"<[^>]+>", "", body_content)  # Remove HTML tags
    return cleaned_body

def format_cleaned_body(body):
    """
    Format the body by adding breaks and making it more readable.
    """
    body = body.replace("\n", " \n").replace("  ", " ")
    # Adding additional line breaks for clarity
    body = body.replace("Please confirm receipt", "\n\nPlease confirm receipt")
    body = body.replace("ATTENTION", "\n\nATTENTION")
    return body

def calculate_phishing_score(ip_data, vt_results, keyword_data):
    score = 0
    
    # Increase score for suspicious IP
    if ip_data and "abuseConfidenceScore" in ip_data and ip_data["abuseConfidenceScore"] > 50:
        score += 2  # Increase score if IP is flagged
    
    # Increase score for suspicious URLs
    if vt_results and len(vt_results) > 0:
        score += len(vt_results)
    
    # Increase score for detected suspicious keywords
    if keyword_data:
        score += sum(len(keywords) for keywords in keyword_data.values())

    return score

def main():
    file_path = input("Enter the path to the email file (eml format): ").strip()

    if not os.path.isfile(file_path):
        print("Error: File not found. Please ensure the path is correct.")
        return

    msg = read_email_file(file_path)
    if not msg:
        print("Error parsing email.")
        return

    # Extract headers and body
    headers = extract_headers(msg)
    cleaned_body = get_cleaned_body(msg)
    formatted_body = format_cleaned_body(cleaned_body)

    # Extract and analyze Authentication Results (SPF, DKIM, DMARC)
    auth_results = parse_authentication_results(headers["Authentication-Results"])

    # Extract IP and domain from Authentication Results
    ip, domain = extract_ip_and_domain_from_authentication_results(headers["Authentication-Results"])
    ip_data = analyze_ip_with_abuseipdb(ip) if ip else None

    # Extract URLs from the body
    urls = re.findall(r'https?://[^\s]+', formatted_body)
    vt_results = analyze_urls_with_virustotal(urls)
    
    # Analyze suspicious keywords
    keyword_data = analyze_keywords_in_body(formatted_body)

    # Calculate phishing score
    phishing_score = calculate_phishing_score(ip_data, vt_results, keyword_data)

    # Ask user if they want to save the results or show on CLI
    save_as_json = input("Do you want to save the results as JSON? (yes/no): ").strip().lower()
    
    result_data = {
        "Email Information": headers,
        "Body (cleaned)": formatted_body,
        
        # Analysis Section 1: Authentication Results
        "Analysis 1: Authentication Results": {
            "SPF": auth_results.get("SPF", "Not Available"),
            "DKIM": auth_results.get("DKIM", "Not Available"),
            "DMARC": auth_results.get("DMARC", "Not Available"),
            "Sender IP": ip,
            "From Domain": domain
        },
        
        # Analysis Section 2: IP Reputation
        "Analysis 2: IP Reputation": ip_data if ip_data else "No IP data available",
        
        # Analysis Section 3: Extracted URLs
        "Analysis 3: Extracted URLs": urls if urls else "No URLs found",
        
        # Analysis Section 3.1: VirusTotal Links
        "Analysis 3.1: VirusTotal Links": vt_results if vt_results else "No VirusTotal results found",
        
        # Analysis Section 3.2: Suspicious Keywords Detected
        "Analysis 3.2: Suspicious Keywords Detected": keyword_data if keyword_data else "No suspicious keywords detected",
        
        # Phishing Score Analysis
        "Phishing Score": phishing_score
    }

    if save_as_json == "yes":
        # Save to a JSON file
        output_file = f"{os.path.splitext(file_path)[0]}_analysis.json"
        with open(output_file, 'w') as f:
            json.dump(result_data, f, indent=4)
        print(f"Results saved to {output_file}")
    else:
        # Print to CLI
        print(json.dumps(result_data, indent=4))

if __name__ == "__main__":
    main()
