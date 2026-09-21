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

// --- REUSABLE LOCATION MAP COMPONENT ---
const LocationMap = ({ data, originatingIp }) => {
  if (!data?.coordinates?.latitude) return <p className="text-slate-500 bg-slate-900 p-4 rounded-lg">No geolocation data available.</p>;
  
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 h-full">
      <div className="md:col-span-2 h-80 rounded-lg overflow-hidden border-2 border-slate-600 z-0 relative">
        <MapContainer 
          key={`${data.coordinates.latitude}-${data.coordinates.longitude}`}
          center={[data.coordinates.latitude, data.coordinates.longitude]} 
          zoom={12} 
          style={{ height: '100%', width: '100%' }}
        >
          <TileLayer attribution='&copy; OpenStreetMap' url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
          <Marker position={[data.coordinates.latitude, data.coordinates.longitude]}>
            <Popup>
              <div className="text-slate-900 text-sm font-bold">
                Origin: {data.city}, {data.country}<br/>
                IP: {originatingIp || data.ip}<br/>
                ISP: {data.isp}
              </div>
            </Popup>
          </Marker>
        </MapContainer>
      </div>
      <div className="space-y-3">
        <div className="bg-slate-900 p-3 rounded-lg border border-slate-700">
          <p className="text-slate-500 text-xs"> IP ADDRESS</p>
          <p className="text-blue-400 font-mono text-xl font-bold">{originatingIp || data.ip}</p>
        </div>
        <div className="bg-slate-900 p-3 rounded-lg border border-slate-700">
          <p className="text-slate-500 text-xs"> PHYSICAL LOCATION</p>
          <p className="text-white text-lg font-bold">{data.city}, {data.country}</p>
          <p className="text-slate-400 text-xs font-mono mt-1">Lat: {data.coordinates.latitude} | Lon: {data.coordinates.longitude}</p>
        </div>
        <div className="bg-slate-900 p-3 rounded-lg border border-slate-700">
          <p className="text-slate-500 text-xs"> ISP / ORGANIZATION</p>
          <p className="text-white text-sm">{data.isp} {data.organization ? `(${data.organization})` : ''}</p>
        </div>
        <div className="bg-slate-900 p-3 rounded-lg border border-slate-700">
          <p className="text-slate-500 text-xs">⚠️ CONNECTION TYPE</p>
          <div className="flex flex-wrap gap-2 mt-2">
            {data.connection_type?.is_proxy && <span className="bg-red-900/50 text-red-300 text-xs px-2 py-1 rounded border border-red-700 font-bold">PROXY</span>}
            {data.connection_type?.is_hosting && <span className="bg-orange-900/50 text-orange-300 text-xs px-2 py-1 rounded border border-orange-700 font-bold">DATACENTER</span>}
            {!data.connection_type?.is_proxy && !data.connection_type?.is_hosting && <span className="bg-green-900/50 text-green-300 text-xs px-2 py-1 rounded border border-green-700 font-bold">RESIDENTIAL</span>}
          </div>
        </div>
        <a href={`https://www.google.com/maps?q=${data.coordinates.latitude},${data.coordinates.longitude}`} target="_blank" rel="noopener noreferrer" className="block w-full text-center bg-blue-600 hover:bg-blue-700 text-white text-sm font-bold py-2 px-4 rounded-lg transition-colors">
          🔗 View on Google Maps
        </a>
      </div>
    </div>
  );
};

function App() {
  const [activeTab, setActiveTab] = useState('email'); // 'email' or 'ip'
  
  // Email States
  const [analysisResult, setAnalysisResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [fileName, setFileName] = useState('');

  // IP States
  const [ipInput, setIpInput] = useState('');
  const [ipResult, setIpResult] = useState(null);
  const [ipLoading, setIpLoading] = useState(false);

  const onDrop = useCallback(async (acceptedFiles) => {
    const file = acceptedFiles[0];
    if (!file) return;
    setFileName(file.name);
    setLoading(true);
    setAnalysisResult(null);
    const formData = new FormData();
    formData.append('file', file);
    try {
      const response = await axios.post('http://127.0.0.1:8000/api/analyze-file', formData, { headers: { 'Content-Type': 'multipart/form-data' } });
      setAnalysisResult(response.data);
    } catch (error) {
      alert("Failed to analyze file. Make sure the backend is running!");
    } finally { setLoading(false); }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop, accept: { 'message/rfc822': ['.eml'], 'text/plain': ['.txt'] }, multiple: false });

  const handleIpLookup = async () => {
    if (!ipInput.trim()) return alert("Please enter an IP address");
    setIpLoading(true);
    setIpResult(null);
    try {
      const response = await axios.post('http://127.0.0.1:8000/api/lookup-ip', { ip: ipInput });
      setIpResult(response.data);
    } catch (error) {
      alert("Failed to lookup IP. Make sure the backend is running!");
    } finally { setIpLoading(false); }
  };

  return (
    <div className="min-h-screen bg-slate-900 text-white p-8 font-sans">
      <header className="mb-8 text-center">
        <h1 className="text-4xl font-bold text-blue-400">SIH26106: Email Forensic Intelligence</h1>
        <p className="text-slate-400 mt-2">AI-Powered Phishing Detection & Precise GeoLocation Tracker</p>
      </header>

      {/* TABS */}
      <div className="max-w-5xl mx-auto mb-8 flex justify-center gap-4">
        <button onClick={() => setActiveTab('email')} className={`px-6 py-3 rounded-lg font-bold transition-all ${activeTab === 'email' ? 'bg-blue-600 text-white shadow-lg' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'}`}>
          📧 Email Forensics
        </button>
        <button onClick={() => setActiveTab('ip')} className={`px-6 py-3 rounded-lg font-bold transition-all ${activeTab === 'ip' ? 'bg-blue-600 text-white shadow-lg' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'}`}>
           IP Intelligence Lookup
        </button>
      </div>

      {/* ================= EMAIL TAB ================= */}
      {activeTab === 'email' && (
        <div className="max-w-7xl mx-auto">
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

          {loading && <div className="text-center"><div className="inline-block animate-spin rounded-full h-12 w-12 border-t-4 border-blue-500 mb-4"></div><p className="text-lg text-blue-400">🤖 Analyzing...</p></div>}

          {analysisResult && analysisResult.status === 'success' && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              <div className="bg-slate-800 p-6 rounded-xl shadow-lg border border-slate-700">
                <h2 className="text-xl font-bold text-slate-300 mb-4">🎯 Risk Assessment</h2>
                <div className="flex items-center justify-between">
                  <div><p className="text-6xl font-bold text-red-500">{analysisResult.risk_assessment.overall_fraud_score}</p><p className="text-slate-400 mt-1">Fraud Score / 100</p></div>
                  <div className={`px-6 py-3 rounded-full font-bold text-lg ${analysisResult.risk_assessment.risk_level === 'HIGH' ? 'bg-red-900/50 text-red-300 border border-red-700' : analysisResult.risk_assessment.risk_level === 'MEDIUM' ? 'bg-yellow-900/50 text-yellow-300 border border-yellow-700' : 'bg-green-900/50 text-green-300 border border-green-700'}`}>{analysisResult.risk_assessment.risk_level}</div>
                </div>
              </div>
              <div className="bg-slate-800 p-6 rounded-xl shadow-lg border border-slate-700">
                <h2 className="text-xl font-bold text-slate-300 mb-4">🤖 AI BERT Analysis</h2>
                <p className="text-2xl font-bold text-blue-400 mb-4 capitalize">{analysisResult.ai_analysis.predicted_category}</p>
                <div className="space-y-2">
                  {Object.entries(analysisResult.ai_analysis.all_scores).map(([label, score]) => (
                    <div key={label} className="flex justify-between text-sm bg-slate-900 p-2 rounded"><span className="text-slate-400 capitalize">{label}</span><span className="text-white font-mono">{score}</span></div>
                  ))}
                </div>
              </div>
              <div className="bg-slate-800 p-6 rounded-xl shadow-lg border border-slate-700">
                <h2 className="text-xl font-bold text-slate-300 mb-4">🔐 Protocol Auth</h2>
                <div className="grid grid-cols-2 gap-4 text-center">
                  <div className={`p-4 rounded-lg font-bold ${analysisResult.authentication.spf === 'Pass' ? 'bg-green-900/50 text-green-300 border border-green-700' : 'bg-red-900/50 text-red-300 border border-red-700'}`}>SPF: {analysisResult.authentication.spf}</div>
                  <div className={`p-4 rounded-lg font-bold ${analysisResult.authentication.dkim === 'Pass' ? 'bg-green-900/50 text-green-300 border border-green-700' : 'bg-red-900/50 text-red-300 border border-red-700'}`}>DKIM: {analysisResult.authentication.dkim}</div>
                </div>
              </div>
              
              {/* Location Map for Email */}
              <div className="bg-slate-800 p-6 rounded-xl shadow-lg border-2 border-red-900/50 lg:col-span-3">
                <h2 className="text-xl font-bold text-red-400 mb-4"> TARGET LOCATION INTELLIGENCE</h2>
                <LocationMap data={analysisResult.forensics.geo_location} originatingIp={analysisResult.forensics.originating_ip} />
              </div>

              <div className="lg:col-span-3 flex justify-center mt-4 mb-8">
                <button onClick={async () => {
                  try {
                    const response = await axios.post('http://127.0.0.1:8000/api/generate-report', analysisResult, { responseType: 'blob' });
                    const url = window.URL.createObjectURL(new Blob([response.data]));
                    const link = document.createElement('a'); link.href = url; link.setAttribute('download', `Forensic_Report.pdf`); document.body.appendChild(link); link.click(); link.parentNode.removeChild(link);
                  } catch (error) { alert("Failed to generate PDF report."); }
                }} className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-8 rounded-lg shadow-lg flex items-center gap-2 transition-all">
                  📄 Download Official Forensic PDF Report
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ================= IP LOOKUP TAB ================= */}
      {activeTab === 'ip' && (
        <div className="max-w-5xl mx-auto">
          <div className="bg-slate-800 p-8 rounded-xl shadow-lg border border-slate-700 mb-8">
            <h2 className="text-2xl font-bold text-slate-300 mb-4">🔍 Trace Any IP Address</h2>
            <div className="flex gap-4">
              <input 
                type="text" 
                value={ipInput}
                onChange={(e) => setIpInput(e.target.value)}
                placeholder="Enter IP Address (e.g., 8.8.8.8 or 198.51.100.45)" 
                className="flex-1 bg-slate-900 border border-slate-600 text-white px-4 py-3 rounded-lg focus:outline-none focus:border-blue-500 font-mono"
              />
              <button 
                onClick={handleIpLookup}
                disabled={ipLoading}
                className="bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 text-white font-bold py-3 px-8 rounded-lg transition-all"
              >
                {ipLoading ? 'Tracing...' : 'Trace IP'}
              </button>
            </div>
          </div>

          {ipLoading && <div className="text-center"><div className="inline-block animate-spin rounded-full h-12 w-12 border-t-4 border-blue-500 mb-4"></div><p className="text-lg text-blue-400"> Tracing IP Location...</p></div>}

          {ipResult && (
            <div className="bg-slate-800 p-6 rounded-xl shadow-lg border-2 border-blue-900/50">
              <h2 className="text-xl font-bold text-blue-400 mb-4">📍 IP GEOLOCATION & INTELLIGENCE</h2>
              <LocationMap data={ipResult} originatingIp={ipInput} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default App;