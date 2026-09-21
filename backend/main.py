from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from email_parser import analyze_email, get_geo_location
from pydantic import BaseModel
from email_parser import analyze_email
import logging
import io
import datetime
from fpdf import FPDF

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 1. Initialize the FastAPI app (THIS MUST BE AT THE TOP)
app = FastAPI(
    title="SIH26106: Email Forensic Intelligence API",
    description="AI-Powered Email Threat Detection and Header Analysis",
    version="1.0.0"
)

# Allow frontend to communicate with this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "SIH26106 Email Forensics API is running. Go to /docs for Swagger UI."}

@app.post("/api/analyze-text")
def analyze_email_text(raw_text: str):
    logger.info("Received text for analysis")
    result = analyze_email(raw_text)
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result["message"])
    return result

@app.post("/api/analyze-file")
async def analyze_email_file(file: UploadFile = File(...)):
    logger.info(f"Received file: {file.filename}")
    contents = await file.read()
    raw_text = contents.decode("utf-8", errors="ignore")
    
    result = analyze_email(raw_text)
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result["message"])
    
    return result

@app.post("/api/generate-report")
def generate_forensic_report(analysis_data: dict):
    """Generates a professional PDF forensic report with prominent location data."""
    try:
        pdf = FPDF()
        pdf.add_page()
        
        # Header
        pdf.set_font("helvetica", "B", 16)
        pdf.set_text_color(41, 128, 185) # Blue
        pdf.cell(0, 10, "SIH26106: Email Forensic Intelligence Report", align="C", new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font("helvetica", "", 10)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 10, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align="R", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        
        # 1. Risk Assessment
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, "1. Risk Assessment", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 11)
        risk = analysis_data.get("risk_assessment", {})
        pdf.cell(0, 8, f"Overall Fraud Score: {risk.get('overall_fraud_score', 'N/A')}/100", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"Risk Level: {risk.get('risk_level', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        
        # 2. Email Metadata
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, "2. Email Metadata", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 10)
        meta = analysis_data.get("metadata", {})
        pdf.cell(0, 6, f"Subject: {meta.get('subject', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"From: {meta.get('from', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"To: {meta.get('to', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

        # 3. LOCATION INTELLIGENCE (NEW & PROMINENT)
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(200, 50, 50) # Red for emphasis
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
            pdf.cell(0, 8, f"Physical Location: {geo.get('city')}, {geo.get('region')}, {geo.get('country')}", new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 8, f"Coordinates: Lat {geo.get('coordinates', {}).get('latitude')}, Lon {geo.get('coordinates', {}).get('longitude')}", new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 8, f"ISP / Organization: {geo.get('isp')} / {geo.get('organization')}", new_x="LMARGIN", new_y="NEXT")
            
            # Connection Type Warning
            conn = geo.get("connection_type", {})
            if conn.get("is_proxy") or conn.get("is_hosting"):
                pdf.set_text_color(200, 50, 50)
                pdf.set_font("helvetica", "B", 10)
                pdf.cell(0, 8, "WARNING: Traffic routed through Proxy or Datacenter/Hosting!", new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(0, 0, 0)
                pdf.set_font("helvetica", "", 10)
            else:
                pdf.cell(0, 8, "Connection Type: Residential / Broadband", new_x="LMARGIN", new_y="NEXT")
                
            # Add a clickable Google Maps link
            lat = geo.get('coordinates', {}).get('latitude')
            lon = geo.get('coordinates', {}).get('longitude')
            if lat and lon:
                pdf.set_text_color(0, 0, 255) # Blue for link
                pdf.cell(0, 8, f"View on Map: https://www.google.com/maps?q={lat},{lon}", new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(0, 0, 0) # Reset color
        else:
            pdf.cell(0, 8, "Location data could not be resolved for this IP.", new_x="LMARGIN", new_y="NEXT")
            
        pdf.ln(5)
        
        # 4. AI Analysis
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 10, "4. AI BERT Analysis", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 10)
        ai = analysis_data.get("ai_analysis", {})
        pdf.cell(0, 6, f"Predicted Category: {ai.get('predicted_category', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"Confidence Score: {ai.get('confidence_score', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        
        # 5. Authentication
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, "5. Protocol Authentication", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 10)
        auth = analysis_data.get("authentication", {})
        pdf.cell(0, 6, f"SPF: {auth.get('spf', 'N/A')} | DKIM: {auth.get('dkim', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
        
        # Footer
        pdf.set_y(-20)
        pdf.set_font("helvetica", "I", 8)
        pdf.set_text_color(150, 150, 150)
        pdf.cell(0, 10, "Generated by SIH26106 Email Forensic Intelligence Platform. For institutional action and law enforcement.", align="C")

        # Return as downloadable file
        pdf_bytes = pdf.output(dest='S').encode('latin1')
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=Forensic_Report_Location_Traced.pdf"}
        )
    except Exception as e:
        return {"status": "error", "message": str(e)}
    class IPRequest(BaseModel):
    ip: str

@app.post("/api/lookup-ip")
def lookup_ip(request: IPRequest):
    """Standalone IP Geolocation and Intelligence Lookup."""
    ip_address = request.ip.strip()
    if not ip_address:
        raise HTTPException(status_code=400, detail="IP address is required")
    
    # Reuse the existing geo-location function
    result = get_geo_location(ip_address)
    return result