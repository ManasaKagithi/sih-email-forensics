import { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import axios from 'axios';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';

// Fix for Leaflet marker icons in React
import icon from 'leaflet/dist/images/marker-icon.png';
import iconShadow from 'leaflet/dist/images/marker-shadow.png';

let DefaultIcon = L.icon({
    iconUrl: icon, shadowUrl: iconShadow,
    iconSize: [25, 41], iconAnchor: [12, 41], popupAnchor: [1, -34], shadowSize: [41, 41]
});
L.Marker.prototype.options.icon = DefaultIcon;

function App() {
  const [analysisResult, setAnalysisResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [fileName, setFileName] = useState('');

  const onDrop = useCallback(async (acceptedFiles) => {
    const file = acceptedFiles[0];
    if (!file) return;

    setFileName(file.name);
    setLoading(true);
    setAnalysisResult(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await axios.post('http://127.0.0.1:8000/api/analyze-file', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      setAnalysisResult(response.data);
    } catch (error) {
      console.error("Error analyzing file:", error);
      alert("Failed to analyze file. Make sure the backend is running!");
    } finally {
      setLoading(false);
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ 
    onDrop, accept: { 'message/rfc822': ['.eml'], 'text/plain': ['.txt'] }, multiple: false 
  });

  const renderIpList = (ips) => {
    if (!ips || ips.length === 0) return <p className="text-slate-500 text-sm">None detected</p>;
    return (
      <div className="space-y-2 mt-2">
        {ips.map((ip, index) => (
          <div key={index} className="flex items-center justify-between bg-slate-900/50 p-2 rounded border border-slate-700">
            <span className="font-mono text-blue-300">{ip}</span>
            <span className="text-xs text-slate-500">Hop {index + 1}</span>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-slate-900 text-white p-8 font-sans">
      <header className="mb-8 text-center">
        <h1 className="text-4xl font-bold text-blue-400">SIH26106: Email Forensic Intelligence</h1>
        <p className="text-slate-400 mt-2">AI-Powered Phishing Detection & Precise GeoLocation Tracker</p>
      </header>

      {/* Upload Zone */}
      <div className="max-w-3xl mx-auto mb-10">
        <div {...getRootProps()} className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-all ${isDragActive ? 'border-blue-500 bg-blue-900/20' : 'border-slate-600 hover:border-blue-400 bg-slate-800'}`}>
          <input {...getInputProps()} />
          {isDragActive ? <p className="text-blue-400 text-xl font-bold">Drop the .eml file here...</p> : (
            <div>
              <p className="text-xl text-slate-300">Drag & drop an <span className="text-blue-400 font-bold">.eml</span> file here, or click to select</p>
              <p className="text-sm text-slate-500 mt-2">Supports .eml and .txt formats</p>
            </div>
          )}
        </div>
        {fileName && <p className="text-center mt-4 text-green-400 font-mono">Selected: {fileName}</p>}
      </div>

      {loading && (
        <div className="max-w-3xl mx-auto text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-t-4 border-blue-500 mb-4"></div>
          <p className="text-lg text-blue-400">🤖 Analyzing with Hugging Face BERT & Tracing IP...</p>
        </div>
      )}

      {/* Results Dashboard */}
      {analysisResult && analysisResult.status === 'success' && (
        <div className="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          
          {/* Risk Score */}
          <div className="bg-slate-800 p-6 rounded-xl shadow-lg border border-slate-700">
            <h2 className="text-xl font-bold text-slate-300 mb-4">🎯 Risk Assessment</h2>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-6xl font-bold text-red-500">{analysisResult.risk_assessment.overall_fraud_score}</p>
                <p className="text-slate-400 mt-1">Fraud Score / 100</p>
              </div>
              <div className={`px-6 py-3 rounded-full font-bold text-lg ${analysisResult.risk_assessment.risk_level === 'HIGH' ? 'bg-red-900/50 text-red-300 border border-red-700' : analysisResult.risk_assessment.risk_level === 'MEDIUM' ? 'bg-yellow-900/50 text-yellow-300 border border-yellow-700' : 'bg-green-900/50 text-green-300 border border-green-700'}`}>
                {analysisResult.risk_assessment.risk_level}
              </div>
            </div>
          </div>

          {/* AI Analysis */}
          <div className="bg-slate-800 p-6 rounded-xl shadow-lg border border-slate-700">
            <h2 className="text-xl font-bold text-slate-300 mb-4">🤖 AI BERT Analysis</h2>
            <p className="text-2xl font-bold text-blue-400 mb-4 capitalize">{analysisResult.ai_analysis.predicted_category}</p>
            <div className="space-y-2">
              {Object.entries(analysisResult.ai_analysis.all_scores).map(([label, score]) => (
                <div key={label} className="flex justify-between text-sm bg-slate-900 p-2 rounded">
                  <span className="text-slate-400 capitalize">{label}</span>
                  <span className="text-white font-mono">{score}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Authentication */}
          <div className="bg-slate-800 p-6 rounded-xl shadow-lg border border-slate-700">
            <h2 className="text-xl font-bold text-slate-300 mb-4">🔐 Protocol Auth</h2>
            <div className="grid grid-cols-2 gap-4 text-center">
              <div className={`p-4 rounded-lg font-bold ${analysisResult.authentication.spf === 'Pass' ? 'bg-green-900/50 text-green-300 border border-green-700' : 'bg-red-900/50 text-red-300 border border-red-700'}`}>SPF: {analysisResult.authentication.spf}</div>
              <div className={`p-4 rounded-lg font-bold ${analysisResult.authentication.dkim === 'Pass' ? 'bg-green-900/50 text-green-300 border border-green-700' : 'bg-red-900/50 text-red-300 border border-red-700'}`}>DKIM: {analysisResult.authentication.dkim}</div>
            </div>
          </div>

          {/* Network Routing Path (Private & Public IPs) */}
          <div className="bg-slate-800 p-6 rounded-xl shadow-lg border border-slate-700 lg:col-span-1">
            <h2 className="text-xl font-bold text-slate-300 mb-4"> Network Routing Path</h2>
            
            <div className="mb-4">
              <h3 className="text-sm font-bold text-blue-400 uppercase tracking-wide">External (Public IPs)</h3>
              <p className="text-xs text-slate-500 mb-1">Internet-facing servers</p>
              {renderIpList(analysisResult.forensics.public_ips)}
            </div>

            <div>
              <h3 className="text-sm font-bold text-purple-400 uppercase tracking-wide">Internal (Private IPs)</h3>
              <p className="text-xs text-slate-500 mb-1">Local network hops (192.168.x.x, 10.x.x.x)</p>
              {renderIpList(analysisResult.forensics.private_ips)}
            </div>
          </div>

          {/* Interactive Map - Spans 2 columns */}
          <div className="bg-slate-800 p-6 rounded-xl shadow-lg border border-slate-700 lg:col-span-2">
            <h2 className="text-xl font-bold text-slate-300 mb-4">📍 Precise Origin Location</h2>
            {analysisResult.forensics.geo_location.coordinates?.latitude ? (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 h-full">
                
                {/* The Map */}
                <div className="md:col-span-2 h-80 rounded-lg overflow-hidden border-2 border-slate-600 z-0">
                  <MapContainer 
                    key={`${analysisResult.forensics.geo_location.coordinates.latitude}-${analysisResult.forensics.geo_location.coordinates.longitude}`}
                    center={[analysisResult.forensics.geo_location.coordinates.latitude, analysisResult.forensics.geo_location.coordinates.longitude]} 
                    zoom={12} 
                    style={{ height: '100%', width: '100%' }}
                  >
                    <TileLayer
                      attribution='&copy; OpenStreetMap'
                      url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                    />
                    <Marker position={[analysisResult.forensics.geo_location.coordinates.latitude, analysisResult.forensics.geo_location.coordinates.longitude]}>
                      <Popup>
                        <div className="text-slate-900 text-sm">
                          <strong>Origin: {analysisResult.forensics.geo_location.city}, {analysisResult.forensics.geo_location.country}</strong><br/>
                          IP: {analysisResult.forensics.originating_ip}<br/>
                          ISP: {analysisResult.forensics.geo_location.isp}
                        </div>
                      </Popup>
                    </Marker>
                  </MapContainer>
                </div>

                {/* Location Details */}
                <div className="space-y-3">
                  <div className="bg-slate-900 p-3 rounded-lg border border-slate-700">
                    <p className="text-slate-500 text-xs"> IP ADDRESS</p>
                    <p className="text-blue-400 font-mono text-lg">{analysisResult.forensics.originating_ip}</p>
                  </div>
                  <div className="bg-slate-900 p-3 rounded-lg border border-slate-700">
                    <p className="text-slate-500 text-xs">📍 CITY / COUNTRY</p>
                    <p className="text-white">{analysisResult.forensics.geo_location.city}, {analysisResult.forensics.geo_location.country}</p>
                  </div>
                  <div className="bg-slate-900 p-3 rounded-lg border border-slate-700">
                    <p className="text-slate-500 text-xs">🏢 ISP / ORG</p>
                    <p className="text-white text-sm">{analysisResult.forensics.geo_location.isp}</p>
                  </div>
                  <div className="bg-slate-900 p-3 rounded-lg border border-slate-700">
                    <p className="text-slate-500 text-xs">⚠️ CONNECTION TYPE</p>
                    <div className="text-sm mt-1">
                      {analysisResult.forensics.geo_location.connection_type?.is_proxy && <p className="text-red-400">Proxy Detected</p>}
                      {analysisResult.forensics.geo_location.connection_type?.is_hosting && <p className="text-yellow-400">Datacenter/Hosting</p>}
                      {!analysisResult.forensics.geo_location.connection_type?.is_proxy && !analysisResult.forensics.geo_location.connection_type?.is_hosting && <p className="text-green-400">Residential/Broadband</p>}
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <p className="text-slate-500 bg-slate-900 p-4 rounded-lg">No geolocation data available.</p>
            )}
          </div>

        </div>
        
      )}
    </div>
    
  );
}

export default App;