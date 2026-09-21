from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, HTMLResponse
from email_parser import analyze_email, get_geo_location
import logging
import io
import datetime
from fpdf import FPDF
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SIH26106: SentinelMail AI", version="2.0.0")

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

# --- IN-MEMORY DATABASE FOR REAL-TIME DASHBOARD ---
analyzed_emails_db = []

@app.get("/")
def read_root():
    return {"message": "SentinelMail AI API is running."}

@app.post("/api/analyze-file")
async def analyze_email_file(file: UploadFile = File(...)):
    contents = await file.read()
    raw_text = contents.decode("utf-8", errors="ignore")
    result = analyze_email(raw_text)
    
    if result.get("status") == "success":
        # Add timestamp and save to our "Ledger"
        result["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        analyzed_emails_db.append(result)
        
    return result

# --- NEW: REAL-TIME DASHBOARD STATS ---
@app.get("/api/dashboard-stats")
def get_dashboard_stats():
    total = len(analyzed_emails_db)
    if total == 0:
        return {"total": 0, "suspicious": 0, "percentage": 0, "highest_risk": 0, "blocks": 0, "activity": [], "categories": []}
    
    suspicious = sum(1 for e in analyzed_emails_db if e.get('risk_assessment', {}).get('risk_level') in ['HIGH', 'MEDIUM'])
    highest_risk = max(e.get('risk_assessment', {}).get('overall_fraud_score', 0) for e in analyzed_emails_db)
    
    # Activity: last 10 emails risk scores
    activity = [{"block": f"#{i+1}", "value": e.get('risk_assessment', {}).get('overall_fraud_score', 0)} for i, e in enumerate(analyzed_emails_db[-10:])]
    
    # Categories
    cats = {"Safe": 0, "Phishing": 0, "BEC": 0}
    for e in analyzed_emails_db:
        cat = e.get('ai_analysis', {}).get('predicted_category', 'legitimate email')
        if 'phishing' in cat: cats["Phishing"] += 1
        elif 'compromise' in cat: cats["BEC"] += 1
        else: cats["Safe"] += 1
        
    categories = [
        {"name": "Safe", "value": cats["Safe"], "color": "#10b981"},
        {"name": "Phishing", "value": cats["Phishing"], "color": "#ef4444"},
        {"name": "BEC", "value": cats["BEC"], "color": "#f97316"}
    ]
    
    return {
        "total": total, "suspicious": suspicious, 
        "percentage": round((suspicious/total)*100, 1),
        "highest_risk": highest_risk, "blocks": total,
        "activity": activity, "categories": categories
    }

# --- NEW: REPORTS ENDPOINT ---
@app.get("/api/reports")
def get_reports():
    return {"reports": analyzed_emails_db}

# --- NEW: SENDER REPUTATION / FLAGGING ---
@app.get("/api/sender-reputation")
def get_sender_reputation(sender_email: str = Query(...)):
    history = [e for e in analyzed_emails_db if sender_email.lower() in e.get('metadata', {}).get('from', '').lower()]
    if not history:
        return {"status": "unknown", "message": "No history found for this sender."}
    
    avg_risk = sum(e.get('risk_assessment', {}).get('overall_fraud_score', 0) for e in history) / len(history)
    last_cat = history[-1].get('ai_analysis', {}).get('predicted_category', 'unknown')
    last_conf = history[-1].get('ai_analysis', {}).get('confidence_score', '0%')
    threat_level = "HIGH" if avg_risk > 60 else "MEDIUM" if avg_risk > 30 else "LOW"
    
    return {
        "sender": sender_email, "emails_seen": len(history),
        "avg_risk_score": round(avg_risk, 1), "threat_level": threat_level,
        "last_category": last_cat, "last_confidence": last_conf,
        "flagged": avg_risk > 50
    }

# --- PDF REPORT GENERATION ---
@app.post("/api/generate-report")
def generate_forensic_report(analysis_data: dict):
    # ... (Keep your existing PDF code here, it works perfectly) ...
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", "B", 16)
        pdf.cell(0, 10, "SentinelMail AI: Forensic Report", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(10)
        pdf.set_font("helvetica", "", 10)
        meta = analysis_data.get("metadata", {})
        pdf.cell(0, 8, f"Subject: {meta.get('subject', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"From: {meta.get('from', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, "Content Preview:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 10)
        pdf.multi_cell(0, 6, analysis_data.get("body_content", "No content"))
        pdf.ln(5)
        forensics = analysis_data.get("forensics", {})
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, "Origin Intelligence:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 10)
        pdf.cell(0, 8, f"IP: {forensics.get('originating_ip', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        geo = forensics.get("geo_location", {})
        pdf.cell(0, 8, f"Location: {geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        
        pdf_bytes = pdf.output(dest='S').encode('latin1')
        return StreamingResponse(io.BytesIO(pdf_bytes), media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=Report.pdf"})
    except Exception as e:
        return {"status": "error", "message": str(e)}