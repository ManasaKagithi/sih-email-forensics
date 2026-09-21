import re
import email
import ipaddress
from email import policy
from typing import Dict, List, Optional, Set
import requests
from transformers import pipeline

# --- LOAD HUGGING FACE BERT MODEL ---
print("🤖 Loading Hugging Face AI Model... Please wait.")
classifier = pipeline("zero-shot-classification", model="typeform/distilbert-base-uncased-mnli")
print("✅ AI Model Loaded Successfully!")

def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private (internal network)"""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False

def extract_all_ips_from_headers(received_headers: List[str]) -> Dict:
    """Extracts all IPs, categorizes them, and finds the true originating IP."""
    ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    
    public_ips: Set[str] = set()
    private_ips: Set[str] = set()
    originating_ip = None

    # Scan headers to find all IPs
    for header in received_headers:
        ips = ip_pattern.findall(header)
        for ip in ips:
            if is_private_ip(ip):
                private_ips.add(ip)
            else:
                public_ips.add(ip)

    # Find the true originating IP (first public IP from the bottom/oldest header)
    for header in reversed(received_headers):
        ips = ip_pattern.findall(header)
        for ip in ips:
            if not is_private_ip(ip):
                originating_ip = ip
                break
        if originating_ip:
            break

    return {
        "originating_ip": originating_ip,
        "public_ips": list(public_ips),
        "private_ips": list(private_ips)
    }

def get_geo_location(ip_address: str) -> Dict:
    """Enhanced geolocation with detailed IP intelligence"""
    if not ip_address:
        return {"status": "No IP found"}
    
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query", timeout=10)
        data = response.json()
        
        if data.get('status') == 'success':
            return {
                "ip": ip_address,
                "country": data.get('country', 'Unknown'),
                "region": data.get('regionName', 'Unknown'),
                "city": data.get('city', 'Unknown'),
                "zip": data.get('zip', 'Unknown'),
                "coordinates": {
                    "latitude": data.get('lat'),
                    "longitude": data.get('lon')
                },
                "timezone": data.get('timezone', 'Unknown'),
                "isp": data.get('isp', 'Unknown'),
                "organization": data.get('org', 'Unknown'),
                "asn": data.get('as', 'Unknown'),
                "connection_type": {
                    "is_mobile": data.get('mobile', False),
                    "is_proxy": data.get('proxy', False),
                    "is_hosting": data.get('hosting', False)
                }
            }
        return {"status": "Lookup failed", "ip": ip_address}
    except Exception as e:
        return {"status": "Error", "message": str(e)}

def analyze_with_bert(subject: str, body: str) -> Dict:
    text_to_analyze = f"{subject} {body[:500]}"
    candidate_labels = ["legitimate email", "phishing attempt", "business email compromise"]
    
    try:
        result = classifier(text_to_analyze, candidate_labels)
        top_label = result['labels'][0]
        top_score = round(result['scores'][0] * 100, 2)
        
        return {
            "ai_model": "Hugging Face DistilBERT (Zero-Shot)",
            "predicted_category": top_label,
            "confidence_score": f"{top_score}%",
            "all_scores": {label: f"{round(score * 100, 2)}%" for label, score in zip(result['labels'], result['scores'])}
        }
    except Exception as e:
        return {"ai_model": "Error", "error": str(e)}

def analyze_email(raw_email_text: str) -> Dict:
    try:
        msg = email.message_from_string(raw_email_text, policy=policy.default)
        
        subject = msg.get('subject', 'No Subject')
        from_addr = msg.get('from', 'Unknown')
        to_addr = msg.get('to', 'Unknown')
        
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    break
        else:
            body = msg.get_payload(decode=True).decode('utf-8', errors='ignore') if msg.get_payload() else ""
        
        auth_results = msg.get('authentication-results', '')
        spf = 'Pass' if 'spf=pass' in auth_results.lower() else 'Fail'
        dkim = 'Pass' if 'dkim=pass' in auth_results.lower() else 'Fail'
        
        # 1. Extract ALL IPs (Public & Private)
        received_headers = msg.get_all('received', [])
        ip_data = extract_all_ips_from_headers(received_headers)
        
        # 2. Get GeoLocation for the Originating Public IP
        geo_location = get_geo_location(ip_data["originating_ip"]) if ip_data["originating_ip"] else {"status": "No IP"}
        
        # 3. AI Analysis
        ai_analysis = analyze_with_bert(subject, body)
        
        # 4. Calculate Fraud Score
        fraud_score = 0
        if spf == 'Fail': fraud_score += 25
        if dkim == 'Fail': fraud_score += 15
        if "phishing attempt" in ai_analysis.get("predicted_category", ""): fraud_score += 40
        if "business email compromise" in ai_analysis.get("predicted_category", ""): fraud_score += 50
        
        # Penalize if it came through a proxy/hosting
        if geo_location.get("connection_type", {}).get("is_proxy"): fraud_score += 10
        if geo_location.get("connection_type", {}).get("is_hosting"): fraud_score += 10
        
        fraud_score = min(fraud_score, 100)
        risk_level = "HIGH" if fraud_score >= 60 else ("MEDIUM" if fraud_score >= 30 else "LOW")
        
        return {
            "status": "success",
            "metadata": {"subject": subject, "from": from_addr, "to": to_addr},
            "authentication": {"spf": spf, "dkim": dkim},
            "forensics": {
                "originating_ip": ip_data["originating_ip"],
                "public_ips": ip_data["public_ips"],
                "private_ips": ip_data["private_ips"],
                "geo_location": geo_location
            },
            "ai_analysis": ai_analysis,
            "risk_assessment": {"overall_fraud_score": fraud_score, "risk_level": risk_level}
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}