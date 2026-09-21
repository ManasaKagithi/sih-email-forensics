from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from email_parser import analyze_email, get_geo_location
import logging
import io
import datetime
from fpdf import FPDF
from pydantic import BaseModel
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 1. Initialize the FastAPI app
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

# --- CORRECTED INDENTATION HERE ---
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

# In-memory database to store tracked clicks (Perfect for Hackathon)
active_tracks = {}

@app.get("/track/{token}")
def track_suspect_visit(token: str, request: Request):
    """
    The 'Honey Link'. When the suspect clicks this, we capture their live IP and location.
    """
    # Get real IP (handling Render/Vercel proxies)
    client_ip = request.client.host
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
        
    # Get live geolocation
    geo_data = get_geo_location(client_ip)
    
    # Save to our tracker
    active_tracks[token] = {
        "ip": client_ip,
        "location": f"{geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}",
        "isp": geo_data.get('isp', 'Unknown'),
        "coordinates": geo_data.get('coordinates'),
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Return success so the user doesn't get suspicious
    return {"status": "tracked", "message": "Visit logged successfully."}

@app.get("/api/get-tracks")
def get_active_tracks():
    """Returns all captured live locations to the dashboard."""
    return {"tracks": active_tracks}

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

        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, "4. Report Details", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 10)
        details = analysis_data.get("details", analysis_data.get("findings", []))
        if isinstance(details, list):
            for detail in details:
                pdf.multi_cell(0, 6, str(detail))
        elif details:
            pdf.multi_cell(0, 6, str(details))

        pdf_bytes = bytes(pdf.output())
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=forensic-report.pdf"},
        )
    except Exception as exc:
        logger.exception("Failed to generate forensic report")
        raise HTTPException(status_code=500, detail="Failed to generate forensic report") from exc