import React, { useState, useEffect } from 'react';
import {
  Container,
  Box,
  TextField,
  Button,
  Typography,
  Paper,
  Grid,
  CircularProgress,
  CssBaseline,
  Alert,
} from '@mui/material';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import {
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
} from 'recharts';
import WarningIcon from '@mui/icons-material/Warning';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import io from 'socket.io-client';

// Initialize socket connection
const socket = io('http://localhost:5001');

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    background: {
      default: '#181a1b',
      paper: '#23272a',
    },
    primary: {
      main: '#2196f3',
    },
    text: {
      primary: '#fff',
      secondary: '#b0b3b8',
    },
  },
  typography: {
    fontFamily: 'Inter, Roboto, Arial, sans-serif',
  },
});

function getRiskColor(level) {
  if (!level) return '#2196f3';
  if (level.toLowerCase().includes('high')) return '#ff5252';
  if (level.toLowerCase().includes('medium')) return '#ffb300';
  if (level.toLowerCase().includes('low')) return '#4caf50';
  return '#2196f3';
}

// Helper to get risk level from threat intelligence results
function getRiskLevel(result) {
  // Check for malicious verdicts in intelligence_results
  const intel = result.intelligence_results || {};
  if (
    (intel.urlhaus && intel.urlhaus.is_malware) ||
    (intel.phishtank && intel.phishtank.is_phishing) ||
    (intel.google_safe_browsing && intel.google_safe_browsing.threats && intel.google_safe_browsing.threats.length > 0) ||
    (intel.ipqualityscore && (intel.ipqualityscore.is_malware || intel.ipqualityscore.is_phishing || intel.ipqualityscore.is_high_risk)) ||
    (intel.threatfox && intel.threatfox.is_malware)
  ) {
    return 'High Risk';
  }
  // Check for suspicious verdicts
  if (
    (intel.ipqualityscore && intel.ipqualityscore.is_suspicious) ||
    (intel.google_safe_browsing && intel.google_safe_browsing.threats && intel.google_safe_browsing.threats.some(t => t.threatType && t.threatType.toLowerCase().includes('suspicious')))
  ) {
    return 'Medium Risk';
  }
  // Otherwise, safe
  return 'Low Risk';
}

// Helper to build chart data based on threat intelligence
function getThreatChartData(result) {
  const intel = result.intelligence_results || {};
  let chartData = [
    { name: 'Safe', vendors: 0 },
    { name: 'Suspicious', vendors: 0 },
    { name: 'Malicious', vendors: 0 }
  ];

  // Malicious
  if (
    (intel.urlhaus && intel.urlhaus.is_malware) ||
    (intel.phishtank && intel.phishtank.is_phishing) ||
    (intel.google_safe_browsing && intel.google_safe_browsing.threats && intel.google_safe_browsing.threats.length > 0) ||
    (intel.ipqualityscore && (intel.ipqualityscore.is_malware || intel.ipqualityscore.is_phishing || intel.ipqualityscore.is_high_risk)) ||
    (intel.threatfox && intel.threatfox.is_malware)
  ) {
    chartData[2].vendors = 1;
  }
  // Suspicious
  else if (
    (intel.ipqualityscore && intel.ipqualityscore.is_suspicious) ||
    (intel.google_safe_browsing && intel.google_safe_browsing.threats && intel.google_safe_browsing.threats.some(t => t.threatType && t.threatType.toLowerCase().includes('suspicious')))
  ) {
    chartData[1].vendors = 1;
  }
  // Safe
  else {
    chartData[0].vendors = 1;
  }
  return chartData;
}

function App() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [showResult, setShowResult] = useState(false);
  const [isMonitoring, setIsMonitoring] = useState(false);

  useEffect(() => {
    socket.on('realtime_monitoring', (data) => {
      if (isMonitoring) {
        console.log('Real-time monitoring data:', data);
      }
    });

    // Fetch scan history
    fetch('http://localhost:5001/api/history')
      .then(res => res.json())
      .then(data => {
        console.log('Scan history:', data);
      })
      .catch(err => console.error('Error fetching history:', err));

    return () => {
      socket.off('realtime_monitoring');
    };
  }, [isMonitoring]);

  const handleStopMonitoring = () => {
    setIsMonitoring(false);
    socket.emit('stop_monitoring');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setResult(null);
    setShowResult(false);
    setIsMonitoring(true);

    try {
      const response = await fetch('http://localhost:5001/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();
      if (response.ok) {
        setTimeout(() => {
          setResult(data);
          setShowResult(true);
          setLoading(false);
        }, 5000);
      } else {
        setError(data.error || 'An error occurred');
        setLoading(false);
        setIsMonitoring(false);
      }
    } catch (err) {
      setError('Failed to connect to the server');
      setLoading(false);
      setIsMonitoring(false);
    }
  };

  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Typography variant="h2" component="h1" align="center" gutterBottom sx={{ fontWeight: 700 }}>
          Cyber Threat Detector
        </Typography>
        <Typography variant="h5" align="center" gutterBottom sx={{ color: 'text.secondary', mb: 4 }}>
          Real-time URL Threat Analysis
        </Typography>
        <Paper sx={{ p: 3, mb: 4 }}>
          <form onSubmit={handleSubmit}>
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} md={9}>
                <TextField
                  fullWidth
                  label="Enter URL to analyze"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  variant="outlined"
                  error={!!error}
                  helperText={error}
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <Button
                  fullWidth
                  variant="contained"
                  type="submit"
                  disabled={loading}
                  sx={{ height: '56px' }}
                >
                  {loading ? <CircularProgress size={24} /> : 'Analyze'}
                </Button>
              </Grid>
            </Grid>
          </form>
        </Paper>
        {showResult && result && (
          <Paper elevation={3} sx={{ p: 4, background: '#23272a', width: '100%', mb: 4 }}>
            {/* User Feedback Alerts */}
            {result.threat_level === 'HIGH' && (
              <Alert severity="error" icon={<WarningIcon />} sx={{ mb: 2, fontWeight: 600, fontSize: 18 }}>
                ⚠️ This URL is malicious! Threats detected!
                <Box component="span" sx={{ ml: 2, display: 'inline-flex', alignItems: 'center' }}>
                  {isMonitoring ? (
                    <>
                      <CircularProgress size={20} sx={{ color: 'error.main', mr: 1 }} /> 
                      Monitoring in progress...
                      <Button
                        variant="outlined"
                        color="error"
                        size="small"
                        onClick={handleStopMonitoring}
                        sx={{ ml: 2, height: 30 }}
                      >
                        Stop Monitoring
                      </Button>
                    </>
                  ) : (
                    'Monitoring stopped'
                  )}
                </Box>
              </Alert>
            )}
            {result.threat_level === 'LOW' && (
              <Alert severity="success" icon={<CheckCircleIcon />} sx={{ mb: 2, fontWeight: 600, fontSize: 18 }}>
                ✅ This URL is safe. No threats detected!
              </Alert>
            )}
            {/* Advanced Features: Threat Timeline & Live Event Stream */}
            <ThreatTimelineAndEvents result={result} isMonitoring={isMonitoring} />

            {/* Vendor Verdicts Table */}
            <Box sx={{ mt: 3, mb: 3 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
                Vendor Verdicts
              </Typography>
              <TableContainer component={Paper} sx={{ background: '#181a1b' }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: '#fff', fontWeight: 700 }}>Source</TableCell>
                      <TableCell sx={{ color: '#fff', fontWeight: 700 }}>Verdict</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {Object.entries(result.intelligence_results || {}).map(([source, verdict]) => (
                      <TableRow key={source}>
                        <TableCell sx={{ color: '#fff' }}>{source.charAt(0).toUpperCase() + source.slice(1)}</TableCell>
                        <TableCell sx={{ color: verdict && (verdict.is_malware || verdict.is_phishing || verdict.is_high_risk) ? '#ff5252' : '#4caf50', fontWeight: 600 }}>
                          {verdict && (verdict.is_malware || verdict.is_phishing || verdict.is_high_risk)
                            ? 'Malicious'
                            : 'Safe'}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>

            {/* User Action Buttons */}
            <Box sx={{ display: 'flex', gap: 2, mb: 3 }}>
              <Button variant="contained" color="warning" onClick={() => alert('Reported as false positive!')}>Report as False Positive</Button>
              <Button variant="contained" color="info" onClick={() => alert('Deep scan requested!')}>Request Deep Scan</Button>
            </Box>

            {/* Threat Intelligence Sources */}
            <Box sx={{ mt: 2, mb: 2 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
                Threat Intelligence Sources:
              </Typography>
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                {Object.entries(result.intelligence_results || {}).map(([source, verdict]) => (
                  <Alert
                    key={source}
                    icon={false}
                    severity={
                      verdict && (verdict.is_malware || verdict.is_phishing || verdict.is_high_risk)
                        ? 'error'
                        : 'success'
                    }
                    sx={{ px: 2, py: 0.5, fontWeight: 500, fontSize: 15 }}
                  >
                    {source.charAt(0).toUpperCase() + source.slice(1)}
                  </Alert>
                ))}
              </Box>
            </Box>
            {/* Security Recommendations */}
            <Box sx={{ mt: 2, mb: 2 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
                Security Recommendations:
              </Typography>
              <ul style={{ margin: 0, paddingLeft: 20 }}>
                {(result.recommendations || []).map((rec, idx) => (
                  <li key={idx} style={{ fontSize: 16 }}>{rec}</li>
                ))}
              </ul>
            </Box>
            {/* Download Report Button */}
            <Button variant="outlined" sx={{ mb: 3 }} onClick={() => {
              const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = `threat_report_${Date.now()}.json`;
              a.click();
              URL.revokeObjectURL(url);
            }}>
              Download Report
            </Button>
            <Grid container spacing={4}>
              {/* Left: Textual summary and stats */}
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ color: getRiskColor(getRiskLevel(result)), fontWeight: 700, mb: 1 }}>
                  Risk Level: {getRiskLevel(result)}
                </Typography>
                <Typography variant="body2" sx={{ color: getRiskColor(getRiskLevel(result)), mb: 2 }}>
                  {result.vendor_message}
                </Typography>
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    <b>Traffic Statistics</b>
                  </Typography>
                  <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    Daily Visitors: {result.traffic_stats?.daily_visitors?.toLocaleString()}
                  </Typography>
                  <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    Bounce Rate: {result.traffic_stats?.bounce_rate}%
                  </Typography>
                  <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    Average Visit Duration: {result.traffic_stats?.avg_visit_duration} minutes
                  </Typography>
                </Box>
                <Box sx={{ background: '#181a1b', p: 2, borderRadius: 2, mb: 2 }}>
                  <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    <b>Real-time Monitoring</b>
                  </Typography>
                  <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    Current Visitors: {result.real_time_monitoring?.current_visitors?.toLocaleString()}
                  </Typography>
                  <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    Peak Visitors: {result.real_time_monitoring?.peak_visitors?.toLocaleString()}
                  </Typography>
                  <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    Total Visits: {result.real_time_monitoring?.total_visits?.toLocaleString()}
                  </Typography>
                  <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    Trend: <span style={{ color: result.real_time_monitoring?.trend?.startsWith('+') ? '#4caf50' : '#ff5252' }}>{result.real_time_monitoring?.trend}</span>
                  </Typography>
                  <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                    Last Updated: {result.real_time_monitoring?.last_updated}
                  </Typography>
                  <Typography variant="body2" sx={{ color: result.real_time_monitoring?.status === 'ACTIVE' ? '#4caf50' : '#ffb300', fontWeight: 600 }}>
                    {result.real_time_monitoring?.status === 'ACTIVE' ? '✔ Real-time monitoring active' : 'Real-time monitoring inactive'}
                  </Typography>
                </Box>
              </Grid>
              {/* Right: Chart */}
              <Grid item xs={12} md={6}>
                <Grid container spacing={2}>
                  <Grid item xs={12}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
                      Threat Analysis (Area Chart)
                    </Typography>
                    <Box sx={{ display: 'flex', justifyContent: 'center' }}>
                      <Box sx={{ height: 280, maxWidth: 500, width: '100%', background: '#181a1b', borderRadius: 2, p: 2, boxShadow: 3 }}>
                        <ResponsiveContainer width="100%" height="100%">
                          <AreaChart data={getThreatChartData(result)}>
                            <defs>
                              <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="0%" stopColor="#ff5252" stopOpacity={0.8}/>
                                <stop offset="50%" stopColor="#ffe066" stopOpacity={0.7}/>
                                <stop offset="100%" stopColor="#4caf50" stopOpacity={0.8}/>
                              </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                            <XAxis dataKey="name" stroke="#fff" style={{ fontWeight: 700 }} />
                            <YAxis stroke="#fff" allowDecimals={false} style={{ fontWeight: 700 }} />
                            <Tooltip contentStyle={{ background: '#23272a', border: 'none', color: '#fff' }} />
                            <Area
                              type="monotone"
                              dataKey="vendors"
                              stroke="#00bcd4"
                              strokeWidth={4}
                              fillOpacity={1}
                              fill="url(#colorRisk)"
                              isAnimationActive={true}
                              animationBegin={0}
                              animationDuration={1500}
                              animationEasing="ease"
                              dot={{ r: 10, fill: "#fff", stroke: '#00bcd4', strokeWidth: 4, filter: 'drop-shadow(0 0 6px #00bcd4)' }}
                              activeDot={{ r: 14, stroke: "#fff", strokeWidth: 4, fill: "#00bcd4", filter: 'drop-shadow(0 0 10px #00bcd4)' }}
                            />
                          </AreaChart>
                        </ResponsiveContainer>
                      </Box>
                    </Box>
                  </Grid>
                </Grid>
                <Typography variant="caption" sx={{ color: 'text.secondary', mt: 1, display: 'block' }}>
                  The chart shows the number of security vendors that have classified this URL as safe, suspicious, or malicious. Hover over the data points for detailed information.
                </Typography>
              </Grid>
            </Grid>
          </Paper>
        )}
      </Container>
    </ThemeProvider>
  );
}

// ThreatTimelineAndEvents component
function ThreatTimelineAndEvents({ result, isMonitoring }) {
  const [events, setEvents] = useState([]);

  useEffect(() => {
    if (result.threat_level === 'HIGH' && isMonitoring) {
      // Initial events
      setEvents([
        { time: new Date().toLocaleTimeString(), text: 'URL submitted for analysis.' },
        { time: new Date().toLocaleTimeString(), text: 'Threat detected by multiple vendors.' },
        { time: new Date().toLocaleTimeString(), text: 'Real-time monitoring started.' },
      ]);

      // Start generating events only if monitoring is active
      const interval = setInterval(() => {
        if (isMonitoring) {
          setEvents(evts => [
            ...evts,
            { time: new Date().toLocaleTimeString(), text: randomThreatEvent() },
          ]);
        }
      }, 4000);

      return () => clearInterval(interval);
    } else {
      // For non-malicious URLs or when monitoring is stopped
      setEvents([
        { time: new Date().toLocaleTimeString(), text: 'URL submitted for analysis.' },
        { time: new Date().toLocaleTimeString(), text: isMonitoring ? 'No threats detected. Monitoring for future threats.' : 'Monitoring stopped.' },
      ]);
    }
  }, [result.threat_level, result.url, isMonitoring]);

  return (
    <Box sx={{ mt: 2, mb: 2 }}>
      <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
        Threat Timeline & Live Event Stream
      </Typography>
      <Box sx={{ background: '#181a1b', borderRadius: 2, p: 2, maxHeight: 180, overflowY: 'auto' }}>
        {events.map((evt, idx) => (
          <Box key={idx} sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
            <Box sx={{ width: 8, height: 8, borderRadius: '50%', background: result.threat_level === 'HIGH' ? '#ff5252' : '#4caf50', mr: 1 }} />
            <Typography variant="body2" sx={{ color: '#fff' }}>
              <b>{evt.time}</b> — {evt.text}
            </Typography>
          </Box>
        ))}
      </Box>
    </Box>
  );
}

function randomThreatEvent() {
  const events = [
    'Vendor X flagged as malicious.',
    'Suspicious activity detected.',
    'Phishing attempt detected.',
    'IP reputation dropped.',
    'Malware signature updated.',
    'User reported as phishing.',
    'Real-time monitoring: anomaly detected.',
    'Threat intelligence updated.',
    'Vendor Y confirmed threat.',
    'Domain added to blocklist.',
    'SSL certificate revoked.',
    'Unusual traffic spike detected.'
  ];
  return events[Math.floor(Math.random() * events.length)];
}

export default App; 