from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from email_parser import analyze_email, get_geo_location
import logging
import io
import datetime
from fpdf import FPDF
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SIH26106: Email Forensic Intelligence API",
    description="AI-Powered Email Threat Detection and Header Analysis",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "SIH26106 Email Forensics API is running."}

@app.post("/api/analyze-text")
def analyze_email_text(raw_text: str):
    result = analyze_email(raw_text)
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result["message"])
    return result

@app.post("/api/analyze-file")
async def analyze_email_file(file: UploadFile = File(...)):
    contents = await file.read()
    raw_text = contents.decode("utf-8", errors="ignore")
    result = analyze_email(raw_text)
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result["message"])
    return result

class IPRequest(BaseModel):
    ip: str

@app.post("/api/lookup-ip")
def lookup_ip(request: IPRequest):
    ip_address = request.ip.strip()
    if not ip_address:
        raise HTTPException(status_code=400, detail="IP address is required")
    return get_geo_location(ip_address)

active_tracks = {}

@app.get("/track/{token}")
def track_suspect_visit(token: str, request: Request):
    client_ip = request.client.host
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
        
    geo_data = get_geo_location(client_ip)
    active_tracks[token] = {
        "ip": client_ip,
        "location": f"{geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}",
        "isp": geo_data.get('isp', 'Unknown'),
        "coordinates": geo_data.get('coordinates'),
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    return {"status": "tracked", "message": "Visit logged successfully."}

@app.get("/api/get-tracks")
def get_active_tracks():
    return {"tracks": active_tracks}

@app.post("/api/generate-report")
def generate_forensic_report(analysis_data: dict):
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", "B", 16)
        pdf.set_text_color(41, 128, 185)
        pdf.cell(0, 10, "SIH26106: Email Forensic Intelligence Report", align="C", new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font("helvetica", "", 10)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 10, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align="R", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, "1. Risk Assessment", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 11)
        risk = analysis_data.get("risk_assessment", {})
        pdf.cell(0, 8, f"Overall Fraud Score: {risk.get('overall_fraud_score', 'N/A')}/100", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"Risk Level: {risk.get('risk_level', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, "2. Email Metadata", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 10)
        meta = analysis_data.get("metadata", {})
        pdf.cell(0, 6, f"Subject: {meta.get('subject', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"From: {meta.get('from', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"To: {meta.get('to', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(200, 50, 50)
        pdf.cell(0, 10, "3. TARGET LOCATION INTELLIGENCE", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("helvetica", "", 10)
        
        forensics = analysis_data.get("forensics", {})
        geo = forensics.get("geo_location", {})
        origin_ip = forensics.get("originating_ip", "Unknown")
        
        pdf.set_font("helvetica", "B", 11)
        pdf.cell(0, 8, f"Originating IP Address: {origin_ip}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 10)
        
        if geo.get("status") != "No IP found" and geo.get("city"):
            pdf.cell(0, 8, f"Physical Location: {geo.get('city')}, {geo.get('country')}", new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 8, f"Coordinates: Lat {geo.get('coordinates', {}).get('latitude')}, Lon {geo.get('coordinates', {}).get('longitude')}", new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 8, f"ISP / Organization: {geo.get('isp')} / {geo.get('organization')}", new_x="LMARGIN", new_y="NEXT")
            
            conn = geo.get("connection_type", {})
            if conn.get("is_proxy") or conn.get("is_hosting"):
                pdf.set_text_color(200, 50, 50)
                pdf.set_font("helvetica", "B", 10)
                pdf.cell(0, 8, "WARNING: Traffic routed through Proxy or Datacenter/Hosting!", new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(0, 0, 0)
                pdf.set_font("helvetica", "", 10)
            else:
                pdf.cell(0, 8, "Connection Type: Residential / Broadband", new_x="LMARGIN", new_y="NEXT")
                
            lat = geo.get('coordinates', {}).get('latitude')
            lon = geo.get('coordinates', {}).get('longitude')
            if lat and lon:
                pdf.set_text_color(0, 0, 255)
                pdf.cell(0, 8, f"View on Map: https://www.google.com/maps?q={lat},{lon}", new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(0, 0, 0)
        else:
            pdf.cell(0, 8, "Location data could not be resolved for this IP.", new_x="LMARGIN", new_y="NEXT")
            
        pdf.ln(5)
        
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, "4. AI BERT Analysis", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 10)
        ai = analysis_data.get("ai_analysis", {})
        pdf.cell(0, 6, f"Predicted Category: {ai.get('predicted_category', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Confidence Score: {ai.get('confidence_score', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, "5. Protocol Authentication", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 10)
        auth = analysis_data.get("authentication", {})
        pdf.cell(0, 6, f"SPF: {auth.get('spf', 'N/A')} | DKIM: {auth.get('dkim', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_y(-20)
        pdf.set_font("helvetica", "I", 8)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 10, "Generated by SIH26106 Email Forensic Intelligence Platform.", align="C")

        pdf_bytes = pdf.output(dest='S').encode('latin1')
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=Forensic_Report.pdf"}
        )
    except Exception as e:
        return {"status": "error", "message": str(e)}