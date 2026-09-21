import { useState, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import axios from 'axios';
import { 
  LayoutDashboard, Mail, Shield, FileText, Activity, AlertTriangle, 
  CheckCircle, Loader2, MapPin, Search
} from 'lucide-react';
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell 
} from 'recharts';

// Leaflet Map Imports
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';
import icon from 'leaflet/dist/images/marker-icon.png';
import iconShadow from 'leaflet/dist/images/marker-shadow.png';

// Fix for default Leaflet marker icons in React
let DefaultIcon = L.icon({
    iconUrl: icon, shadowUrl: iconShadow,
    iconSize: [25, 41], iconAnchor: [12, 41], popupAnchor: [1, -34], shadowSize: [41, 41]
});
L.Marker.prototype.options.icon = DefaultIcon;

const API_URL = 'https://sih-email-forensics-1zcv.onrender.com'; // Your Render URL

// ==========================================
// MAIN APP COMPONENT
// ==========================================
function App() {
  const [activePage, setActivePage] = useState('dashboard');
  const [refreshTrigger, setRefreshTrigger] = useState(0); 

  const triggerRefresh = () => setRefreshTrigger(prev => prev + 1);

  return (
    <div className="flex min-h-screen bg-[#0B1120] text-white font-sans">
      {/* Sidebar */}
      <aside className="w-64 bg-[#0a0f1c] border-r border-slate-800 flex flex-col fixed h-full z-10">
        <div className="p-5 flex items-center gap-3 border-b border-slate-800">
          <div className="w-10 h-10 bg-cyan-500 rounded-lg flex items-center justify-center font-bold text-white text-xl">S</div>
          <div>
            <h1 className="font-bold text-white text-sm">SentinelMail</h1>
            <p className="text-[10px] text-slate-400 uppercase tracking-wider">AI Cyber Intelligence</p>
          </div>
        </div>
        <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
          {[
            { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
            { id: 'analyzer', label: 'Email Analyzer', icon: Mail },
            { id: 'geo', label: 'GeoLocation Intel', icon: MapPin }, // NEW TAB
            { id: 'reports', label: 'Reports Ledger', icon: FileText },
            { id: 'reputation', label: 'Sender Reputation', icon: Shield },
          ].map((item) => {
            const Icon = item.icon;
            return (
              <button key={item.id} onClick={() => setActivePage(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all ${activePage === item.id ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30' : 'text-slate-400 hover:bg-slate-800/50 hover:text-white border border-transparent'}`}>
                <Icon size={16} /> <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </aside>

      {/* Main Content */}
      <main className="flex-1 ml-64 p-6 overflow-y-auto">
        {activePage === 'dashboard' && <DashboardPage refreshTrigger={refreshTrigger} />}
        {activePage === 'analyzer' && <EmailAnalyzerPage onAnalysisComplete={triggerRefresh} />}
        {activePage === 'geo' && <GeoLocationPage />}
        {activePage === 'reports' && <ReportsPage refreshTrigger={refreshTrigger} />}
        {activePage === 'reputation' && <ReputationPage />}
      </main>
    </div>
  );
}

// ==========================================
// DASHBOARD PAGE
// ==========================================
function DashboardPage({ refreshTrigger }) {
  const [stats, setStats] = useState({
    total: 0, suspicious: 0, percentage: 0, highest_risk: 0, blocks: 0,
    activity: [],
    categories: [
      { name: "Safe", value: 0, color: "#10b981" },
      { name: "Phishing", value: 0, color: "#ef4444" },
      { name: "BEC", value: 0, color: "#f97316" }
    ]
  });

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await axios.get(`${API_URL}/api/dashboard-stats`);
        setStats(prev => ({ ...prev, ...res.data }));
      } catch (e) { console.error("Dashboard fetch error:", e); }
    };
    fetchStats();
  }, [refreshTrigger]);

  const safeStats = {
    total: stats.total ?? 0, suspicious: stats.suspicious ?? 0,
    percentage: stats.percentage ?? 0, highest_risk: stats.highest_risk ?? 0,
    blocks: stats.blocks ?? 0, activity: stats.activity ?? [],
    categories: stats.categories ?? []
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-xs text-cyan-400 uppercase tracking-widest font-semibold mb-1">SOC / Incident Response</p>
          <h1 className="text-3xl font-bold text-white">Security Operations Dashboard</h1>
        </div>
        <div className="flex items-center gap-2 bg-slate-800/50 border border-slate-700 px-4 py-2 rounded-lg">
          <div className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></div>
          <span className="text-xs text-emerald-400 font-semibold">SYSTEM ONLINE</span>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Emails Verified" value={safeStats.total} sub={`${safeStats.blocks} ledger blocks`} color="text-white" icon={CheckCircle} />
        <StatCard label="Suspicious Caught" value={safeStats.suspicious} sub={`${safeStats.percentage}% threat ratio`} color="text-red-400" icon={AlertTriangle} />
        <StatCard label="Highest Risk Score" value={safeStats.highest_risk} sub="Peak threat detected" color="text-orange-400" icon={Activity} />
        <StatCard label="Ledger Blocks" value={safeStats.blocks} sub="Immutable records" color="text-cyan-400" icon={Shield} />
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
          <h3 className="text-lg font-bold text-white mb-4">Real-Time Threat Activity</h3>
          {safeStats.activity.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={safeStats.activity}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="block" stroke="#64748b" style={{ fontSize: '12px' }} />
                <YAxis stroke="#64748b" style={{ fontSize: '12px' }} domain={[0, 100]} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }} />
                <Line type="monotone" dataKey="value" stroke="#06b6d4" strokeWidth={2} dot={{ fill: '#06b6d4', r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[250px] flex items-center justify-center text-slate-500 text-sm">No threat activity recorded yet.</div>
          )}
        </div>

        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
          <h3 className="text-lg font-bold text-white mb-4">Threat Categories</h3>
          {safeStats.categories.some(c => c.value > 0) ? (
            <>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={safeStats.categories} cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={2} dataKey="value" stroke="none">
                    {safeStats.categories.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.color} />)}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex justify-center gap-4 mt-2">
                {safeStats.categories.map(cat => (
                  <div key={cat.name} className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: cat.color }}></div>
                    <span className="text-xs text-slate-300">{cat.name} ({cat.value})</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="h-[250px] flex items-center justify-center text-slate-500 text-sm">No categories recorded yet.</div>
          )}
        </div>
      </div>
    </div>
  );
}

// ==========================================
// GEOLOCATION PAGE (NEW)
// ==========================================
function GeoLocationPage() {
  const [ipInput, setIpInput] = useState('');
  const [ipResult, setIpResult] = useState(null);
  const [ipLoading, setIpLoading] = useState(false);

  const handleIpLookup = async () => {
    if (!ipInput.trim()) return alert("Please enter an IP address");
    setIpLoading(true);
    setIpResult(null);
    try {
      const response = await axios.post(`${API_URL}/api/lookup-ip`, { ip: ipInput });
      setIpResult(response.data);
    } catch {
      alert("Failed to lookup IP. Make sure the backend is running!");
    } finally { setIpLoading(false); }
  };

  return (
    <div className="space-y-6">
      <div>
        <p className="text-xs text-cyan-400 uppercase tracking-widest font-semibold mb-1">Network Intelligence</p>
        <h1 className="text-3xl font-bold text-white">GeoLocation Tracker</h1>
      </div>

      {/* Search Box */}
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6">
        <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <Search size={20} className="text-cyan-400" /> Trace IP Address
        </h2>
        <div className="flex gap-4">
          <input 
            type="text" 
            value={ipInput}
            onChange={(e) => setIpInput(e.target.value)}
            placeholder="Enter IP Address (e.g., 8.8.8.8 or 198.51.100.45)" 
            className="flex-1 bg-slate-800 border border-slate-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:border-cyan-500 font-mono"
          />
          <button 
            onClick={handleIpLookup}
            disabled={ipLoading}
            className="bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-600 text-white font-bold py-3 px-8 rounded-lg transition-all flex items-center gap-2"
          >
            {ipLoading ? <Loader2 className="animate-spin" size={20} /> : <MapPin size={20} />}
            {ipLoading ? 'Tracing...' : 'Trace IP'}
          </button>
        </div>
      </div>

      {ipLoading && (
        <div className="text-center py-16">
          <Loader2 className="animate-spin text-cyan-400 mx-auto mb-4" size={50} />
          <p className="text-slate-400">Querying global IP databases and satellite mapping...</p>
        </div>
      )}

      {/* Results Map & Details */}
      {ipResult && ipResult.coordinates?.latitude && (
        <div className="grid grid-cols-3 gap-6">
          {/* Map Container */}
          <div className="col-span-2 bg-slate-900/50 border border-slate-800 rounded-xl p-4 h-[400px]">
            <MapContainer 
              center={[ipResult.coordinates.latitude, ipResult.coordinates.longitude]} 
              zoom={12} 
              style={{ height: '100%', width: '100%', borderRadius: '8px' }}
            >
              <TileLayer attribution='&copy; OpenStreetMap' url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
              <Marker position={[ipResult.coordinates.latitude, ipResult.coordinates.longitude]}>
                <Popup>
                  <div className="text-slate-900 text-sm font-bold">
                    Origin: {ipResult.city}, {ipResult.country}<br/>
                    IP: {ipResult.ip}<br/>
                    ISP: {ipResult.isp}
                  </div>
                </Popup>
              </Marker>
            </MapContainer>
          </div>

          {/* Details Container */}
          <div className="col-span-1 space-y-4">
            <DetailCard label="IP Address" value={ipResult.ip} color="text-cyan-400" mono />
            <DetailCard label="Physical Location" value={`${ipResult.city}, ${ipResult.country}`} />
            <DetailCard label="ISP / Organization" value={ipResult.isp} />
            <DetailCard label="Coordinates" value={`Lat: ${ipResult.coordinates.latitude}\nLon: ${ipResult.coordinates.longitude}`} mono small />
            
            <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700/50">
              <p className="text-slate-400 text-xs uppercase tracking-wider mb-2">Connection Type</p>
              <div className="flex flex-wrap gap-2">
                {ipResult.connection_type?.is_proxy && <span className="bg-red-900/30 text-red-400 border border-red-900 px-2 py-1 rounded text-xs font-bold">PROXY</span>}
                {ipResult.connection_type?.is_hosting && <span className="bg-orange-900/30 text-orange-400 border border-orange-900 px-2 py-1 rounded text-xs font-bold">DATACENTER</span>}
                {!ipResult.connection_type?.is_proxy && !ipResult.connection_type?.is_hosting && <span className="bg-emerald-900/30 text-emerald-400 border border-emerald-900 px-2 py-1 rounded text-xs font-bold">RESIDENTIAL</span>}
              </div>
            </div>

            <a 
              href={`https://www.google.com/maps?q=${ipResult.coordinates.latitude},${ipResult.coordinates.longitude}`} 
              target="_blank" 
              rel="noopener noreferrer" 
              className="block w-full text-center bg-slate-800 hover:bg-slate-700 text-white text-sm font-bold py-3 rounded-lg transition-colors border border-slate-700"
            >
              🔗 View Exact Location on Google Maps
            </a>
          </div>
        </div>
      )}

      {ipResult && !ipResult.coordinates?.latitude && (
        <div className="bg-red-900/20 border border-red-800 rounded-xl p-6 text-center text-red-400">
          Could not resolve location for this IP. It may be a private or reserved address.
        </div>
      )}
    </div>
  );
}

// Helper for GeoLocation Details
function DetailCard({ label, value, color = "text-white", mono = false, small = false }) {
  return (
    <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700/50">
      <p className="text-slate-400 text-xs uppercase tracking-wider mb-1">{label}</p>
      <p className={`${color} ${mono ? 'font-mono' : ''} ${small ? 'text-xs' : 'text-lg'} font-bold whitespace-pre-wrap`}>{value}</p>
    </div>
  );
}

// ==========================================
// EMAIL ANALYZER PAGE
// ==========================================
function EmailAnalyzerPage({ onAnalysisComplete }) {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);

  const onDrop = (acceptedFiles) => {
    const file = acceptedFiles[0];
    if (file) { setSelectedFile(file); setResult(null); }
  };

  const handleAnalyze = async () => {
    if (!selectedFile) return;
    setLoading(true);
    const formData = new FormData();
    formData.append('file', selectedFile);
    
    try {
      const response = await axios.post(`${API_URL}/api/analyze-file`, formData, { headers: { 'Content-Type': 'multipart/form-data' } });
      setResult(response.data);
      if (onAnalysisComplete) onAnalysisComplete(); 
    } catch (error) { alert("Failed to analyze file."); }
    finally { setLoading(false); }
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop, accept: { 'message/rfc822': ['.eml'] }, multiple: false });

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <h1 className="text-3xl font-bold text-white mb-6">Email Analyzer</h1>
      
      <div {...getRootProps()} className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all ${isDragActive ? 'border-cyan-500 bg-cyan-900/10' : 'border-slate-700 hover:border-cyan-500/50 bg-slate-900/50'}`}>
        <input {...getInputProps()} />
        {isDragActive ? <p className="text-cyan-400 text-xl font-bold">Drop the .eml file here...</p> : (
          <div>
            <Mail className="mx-auto h-12 w-12 text-slate-400 mb-4" />
            <p className="text-xl text-slate-300">Drag & drop an <span className="text-cyan-400 font-bold">.eml</span> file here</p>
            <p className="text-sm text-slate-500 mt-2">AI will analyze content, headers, and location in real-time</p>
          </div>
        )}
      </div>

      {selectedFile && !result && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-cyan-500/20 rounded-lg flex items-center justify-center">
              <FileText className="text-cyan-400" size={24} />
            </div>
            <div>
              <p className="text-white font-semibold">{selectedFile.name}</p>
              <p className="text-slate-400 text-sm">{(selectedFile.size / 1024).toFixed(2)} KB</p>
            </div>
          </div>
          <button onClick={handleAnalyze} disabled={loading}
            className="bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-600 text-white font-bold py-3 px-8 rounded-lg transition-all flex items-center gap-2">
            {loading ? <Loader2 className="animate-spin" size={20} /> : <Activity size={20} />}
            {loading ? 'Analyzing...' : 'Analyze Email'}
          </button>
        </div>
      )}

      {loading && !result && (
        <div className="text-center py-16">
          <Loader2 className="animate-spin text-cyan-400 mx-auto mb-4" size={50} />
          <p className="text-slate-400">AI is analyzing email headers, content, and tracing IP location...</p>
        </div>
      )}

      {result && result.status === 'success' && (
        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex justify-between items-center border-b border-slate-800 pb-4">
            <div>
              <h2 className="text-xl font-bold text-white">Analysis Result</h2>
              <p className="text-slate-400 text-sm mt-1">Email analyzed successfully</p>
            </div>
            <div className="flex items-center gap-3">
              <span className={`px-4 py-2 rounded-full font-bold text-sm ${result.risk_assessment.risk_level === 'HIGH' ? 'bg-red-900/50 text-red-400 border border-red-800' : result.risk_assessment.risk_level === 'MEDIUM' ? 'bg-yellow-900/50 text-yellow-400 border border-yellow-800' : 'bg-emerald-900/50 text-emerald-400 border border-emerald-800'}`}>
                {result.risk_assessment.risk_level} RISK ({result.risk_assessment.overall_fraud_score}/100)
              </span>
              <button onClick={() => { setSelectedFile(null); setResult(null); }} className="bg-slate-800 hover:bg-slate-700 text-white px-4 py-2 rounded-lg text-sm transition">
                Analyze Another
              </button>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 text-sm">
            <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700/50">
              <span className="text-slate-400 text-xs uppercase tracking-wider">Subject</span> 
              <p className="text-white mt-1 font-medium">{result.metadata.subject}</p>
            </div>
            <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700/50">
              <span className="text-slate-400 text-xs uppercase tracking-wider">From</span> 
              <p className="text-white mt-1 font-mono text-xs break-all">{result.metadata.from}</p>
            </div>
            <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700/50">
              <span className="text-slate-400 text-xs uppercase tracking-wider">AI Category</span> 
              <p className="text-cyan-400 mt-1 capitalize font-medium">{result.ai_analysis.predicted_category}</p>
            </div>
            <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700/50">
              <span className="text-slate-400 text-xs uppercase tracking-wider">Originating IP</span> 
              <p className="text-white mt-1 font-mono">{result.forensics.originating_ip || 'Hidden / Localhost'}</p>
            </div>
          </div>

          <div className="bg-slate-800/50 p-4 rounded-lg border border-slate-700/50">
            <h3 className="text-sm font-bold text-slate-300 mb-4 flex items-center gap-2">
              <Activity size={16} className="text-cyan-400" /> Network Routing Path
            </h3>
            <div className="grid grid-cols-2 gap-6">
              <div>
                <p className="text-xs text-cyan-400 uppercase font-bold mb-3 tracking-wider">External (Public IPs)</p>
                {result.forensics.public_ips && result.forensics.public_ips.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {result.forensics.public_ips.map((ip, i) => (
                      <span key={i} className="bg-slate-900 border border-cyan-900/50 text-cyan-300 px-3 py-1.5 rounded font-mono text-xs shadow-sm">{ip}</span>
                    ))}
                  </div>
                ) : <p className="text-slate-500 text-xs italic">No external IPs detected in headers.</p>}
              </div>
              <div>
                <p className="text-xs text-purple-400 uppercase font-bold mb-3 tracking-wider">Internal (Private IPs)</p>
                {result.forensics.private_ips && result.forensics.private_ips.length > 0 ? (
                  <div className="flex flex-wrap gap-2">
                    {result.forensics.private_ips.map((ip, i) => (
                      <span key={i} className="bg-slate-900 border border-purple-900/50 text-purple-300 px-3 py-1.5 rounded font-mono text-xs shadow-sm">{ip}</span>
                    ))}
                  </div>
                ) : <p className="text-slate-500 text-xs italic">No internal/private IPs detected.</p>}
              </div>
            </div>
          </div>

          <div className="bg-emerald-900/20 border border-emerald-800/50 rounded-lg p-4 flex items-center gap-3">
            <CheckCircle className="text-emerald-400" size={24} />
            <div>
              <p className="text-emerald-400 font-semibold">Analysis Complete!</p>
              <p className="text-slate-400 text-sm">Dashboard and Reports Ledger have been updated with new threat intelligence data.</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ==========================================
// REPORTS PAGE
// ==========================================
function ReportsPage({ refreshTrigger }) {
  const [reports, setReports] = useState([]);

  useEffect(() => {
    axios.get(`${API_URL}/api/reports`).then(res => setReports(res.data.reports || [])).catch(console.error);
  }, [refreshTrigger]);

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold text-white">Reports Ledger</h1>
      <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden">
        <table className="w-full text-sm text-left">
          <thead className="bg-slate-800/50 text-slate-400 uppercase text-xs">
            <tr>
              <th className="p-4">Sender</th>
              <th className="p-4">Subject / Content</th>
              <th className="p-4">Risk</th>
              <th className="p-4">IP & Location</th>
              <th className="p-4">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {reports.map((r, i) => (
              <tr key={i} className="hover:bg-slate-800/30 transition">
                <td className="p-4 font-mono text-slate-300">{r.metadata.from}</td>
                <td className="p-4">
                  <p className="text-white font-semibold">{r.metadata.subject}</p>
                  <p className="text-slate-500 text-xs mt-1 line-clamp-2">{r.body_content || 'No content preview'}</p>
                </td>
                <td className="p-4">
                  <span className={`px-2 py-1 rounded text-xs font-bold ${r.risk_assessment.risk_level === 'HIGH' ? 'bg-red-900/50 text-red-400' : 'bg-emerald-900/50 text-emerald-400'}`}>
                    {r.risk_assessment.overall_fraud_score} ({r.risk_assessment.risk_level})
                  </span>
                </td>
                <td className="p-4 text-slate-300">
                  <p className="font-mono text-xs">{r.forensics.originating_ip || 'N/A'}</p>
                  <p className="text-slate-500 text-xs">{r.forensics.geo_location?.city}, {r.forensics.geo_location?.country}</p>
                </td>
                <td className="p-4 text-slate-400 text-xs">{r.timestamp}</td>
              </tr>
            ))}
            {reports.length === 0 && <tr><td colSpan="5" className="p-8 text-center text-slate-500">No reports generated yet. Analyze an email to see it here.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ==========================================
// REPUTATION PAGE
// ==========================================
function ReputationPage() {
  const [email, setEmail] = useState('');
  const [data, setData] = useState(null);

  const checkReputation = async () => {
    if (!email) return;
    try {
      const res = await axios.get(`${API_URL}/api/sender-reputation`, { params: { sender_email: email } });
      setData(res.data);
    } catch { setData({ status: 'error', message: 'Failed to fetch.' }); }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <h1 className="text-3xl font-bold text-white">Sender Reputation & Flagging</h1>
      <p className="text-slate-400">Check if a sender has been flagged based on past analyzed activities.</p>
      
      <div className="flex gap-4">
        <input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="Enter sender email" 
          className="flex-1 bg-slate-900 border border-slate-700 text-white px-4 py-3 rounded-lg focus:outline-none focus:border-cyan-500" />
        <button onClick={checkReputation} className="bg-cyan-600 hover:bg-cyan-700 text-white font-bold py-3 px-6 rounded-lg transition">Check History</button>
      </div>

      {data && data.status !== 'error' && data.status !== 'unknown' && (
        <div className={`bg-slate-900/50 border rounded-xl p-6 ${data.flagged ? 'border-red-700' : 'border-emerald-700'}`}>
          <div className="flex items-center gap-3 mb-4">
            {data.flagged ? <AlertTriangle className="text-red-400" size={32} /> : <CheckCircle className="text-emerald-400" size={32} />}
            <h2 className="text-2xl font-bold text-white">{data.flagged ? 'FLAGGED SENDER' : 'Clean Sender'}</h2>
          </div>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div className="bg-slate-800/50 p-3 rounded-lg"><span className="text-slate-400">Emails Seen:</span> <p className="text-white text-lg font-bold">{data.emails_seen}</p></div>
            <div className="bg-slate-800/50 p-3 rounded-lg"><span className="text-slate-400">Avg Risk Score:</span> <p className="text-white text-lg font-bold">{data.avg_risk_score}/100</p></div>
            <div className="bg-slate-800/50 p-3 rounded-lg"><span className="text-slate-400">Threat Level:</span> <p className={`text-lg font-bold ${data.threat_level === 'HIGH' ? 'text-red-400' : 'text-emerald-400'}`}>{data.threat_level}</p></div>
            <div className="bg-slate-800/50 p-3 rounded-lg"><span className="text-slate-400">Last Category:</span> <p className="text-cyan-400 text-lg font-bold capitalize">{data.last_category}</p></div>
          </div>
        </div>
      )}
      {data && data.status === 'unknown' && <div className="bg-slate-800/50 p-6 rounded-xl text-center text-slate-400">{data.message}</div>}
    </div>
  );
}

// ==========================================
// REUSABLE COMPONENTS
// ==========================================
function StatCard({ label, value, sub, color, icon: Icon }) {
  return (
    <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition">
      <div className="flex items-center justify-between mb-2">
        <p className="text-xs text-slate-400 uppercase tracking-wider">{label}</p>
        <Icon size={16} className={color} />
      </div>
      <p className={`text-3xl font-bold ${color}`}>{value}</p>
      <p className="text-xs text-slate-500 mt-1">{sub}</p>
    </div>
  );
}

export default App;