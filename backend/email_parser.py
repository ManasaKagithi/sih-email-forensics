import re
import email
import ipaddress
from email import policy
from typing import Dict, List, Optional, Set
import requests

# Hugging Face Free Inference API URL for Zero-Shot Classification
HF_API_URL = "https://api-inference.huggingface.co/models/typeform/distilbert-base-uncased-mnli"
HF_HEADERS = {"Content-Type": "application/json"} # Add "Authorization": "Bearer YOUR_TOKEN" later if you hit rate limits

def is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False

def extract_all_ips_from_headers(received_headers: List[str]) -> Dict:
    ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    public_ips, private_ips, originating_ip = set(), set(), None

    for header in received_headers:
        for ip in ip_pattern.findall(header):
            (private_ips if is_private_ip(ip) else public_ips).add(ip)

    for header in reversed(received_headers):
        for ip in ip_pattern.findall(header):
            if not is_private_ip(ip):
                originating_ip = ip
                break
        if originating_ip:
            break

    return {"originating_ip": originating_ip, "public_ips": list(public_ips), "private_ips": list(private_ips)}

def get_geo_location(ip_address: str) -> Dict:
    if not ip_address:
        return {"status": "No IP found"}
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,country,regionName,city,lat,lon,isp,org,proxy,hosting", timeout=10)
        data = response.json()
        if data.get('status') == 'success':
            return {
                "ip": ip_address, "country": data.get('country', 'Unknown'), "city": data.get('city', 'Unknown'),
                "coordinates": {"latitude": data.get('lat'), "longitude": data.get('lon')},
                "isp": data.get('isp', 'Unknown'), "organization": data.get('org', 'Unknown'),
                "connection_type": {"is_proxy": data.get('proxy', False), "is_hosting": data.get('hosting', False)}
            }
        return {"status": "Lookup failed", "ip": ip_address}
    except Exception as e:
        return {"status": "Error", "message": str(e)}

def analyze_with_huggingface_cloud(subject: str, body: str) -> Dict:
    """
    Sends text to Hugging Face's free cloud API for real BERT Zero-Shot Classification.
    Uses almost 0MB of RAM on Render!
    """
    text_to_analyze = f"{subject} {body[:500]}"
    payload = {
        "inputs": text_to_analyze,
        "parameters": {
            "candidate_labels": ["legitimate email", "phishing attempt", "business email compromise"]
        }
    }
    
    try:
        # Timeout set to 15s to prevent Render from hanging if HF is cold-starting
        response = requests.post(HF_API_URL, headers=HF_HEADERS, json=payload, timeout=15)
        
        if response.status_code == 200:
            result = response.json()
            labels = result.get('labels', [])
            scores = result.get('scores', [])
            
            top_label = labels[0] if labels else "legitimate email"
            top_score = round(scores[0] * 100, 2) if scores else 0.0
            
            return {
                "ai_model": "Hugging Face DistilBERT (Cloud Inference API)",
                "predicted_category": top_label,
                "confidence_score": f"{top_score}%",
                "all_scores": {label: f"{round(score * 100, 2)}%" for label, score in zip(labels, scores)}
            }
        else:
            # Fallback if HF API is rate-limited or cold
            return {
                "ai_model": "Hugging Face API (Rate Limited/Cold)",
                "predicted_category": "legitimate email",
                "confidence_score": "50.0%",
                "all_scores": {"legitimate email": "50.0%", "phishing attempt": "25.0%", "business email compromise": "25.0%"}
            }
    except Exception as e:
        return {
            "ai_model": "Hugging Face API Error",
            "predicted_category": "legitimate email",
            "confidence_score": "50.0%",
            "all_scores": {"legitimate email": "50.0%", "phishing attempt": "25.0%", "business email compromise": "25.0%"}
        }

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
        
        ip_data = extract_all_ips_from_headers(msg.get_all('received', []))
        geo_location = get_geo_location(ip_data["originating_ip"]) if ip_data["originating_ip"] else {"status": "No IP"}
        
        # Call the Cloud AI
        ai_analysis = analyze_with_huggingface_cloud(subject, body)
        
        # Calculate Fraud Score
        fraud_score = 0
        if spf == 'Fail': fraud_score += 25
        if dkim == 'Fail': fraud_score += 15
        
        if "phishing attempt" in ai_analysis.get("predicted_category", ""): fraud_score += 40
        if "business email compromise" in ai_analysis.get("predicted_category", ""): fraud_score += 50
        
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