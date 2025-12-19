
"use client";

import { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Activity, Network, TrendingUp, TrendingDown, Minus } from 'lucide-react';

const API_URL = 'http://localhost:3001';

interface IcmpRow {
  Timestamp: string;
  IP: string;
  SysName: string;
  SysUpTime: string;
  ICMP_In_Echos: string | number;
  ICMP_In_Echo_Replies: string | number;
  ICMP_Out_Echos: string | number;
  ICMP_Out_Echo_Replies: string | number;
}

interface RouteRow {
  Timestamp: string;
  IP: string;
  Destination: string;
  Mask: string;
  NextHop: string;
  IfIndex: string;
}

interface QueryResult {
  oid: string;
  value: string;
  type: string;
}

interface DeviceItem {
  name: string;
  ip: string;
  role: string;
}

export default function NetworkDashboard() {
  const [icmpData, setIcmpData] = useState<IcmpRow[]>([]);
  const [routeData, setRouteData] = useState<RouteRow[]>([]);
  const [stats, setStats] = useState<{ [key: string]: { current: number; average: string; max: number; min: number } }>({});
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('icmp');
  const [queryOid, setQueryOid] = useState('1.3.6.1.2.1.1.5.0');
  const [queryType, setQueryType] = useState<'get' | 'getnext'>('get');
  const [queryResult, setQueryResult] = useState<QueryResult | null>(null);
  const [queryLoading, setQueryLoading] = useState(false);
  const [queryError, setQueryError] = useState<string | null>(null);
  const [devices, setDevices] = useState<DeviceItem[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<string>("all");

  useEffect(() => {
    fetchData();
    // Load device list for SNMP Query Tool
    fetch(`${API_URL}/api/devices`).then(r => r.json()).then((list: DeviceItem[]) => {
      setDevices(list);
    }).catch(() => {});
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const [icmpRes, routeRes] = await Promise.all([
        fetch(`${API_URL}/api/icmp-logs`),
        fetch(`${API_URL}/api/route-logs`)
      ]);
      
      const icmp = await icmpRes.json();
      const route = await routeRes.json();
      
      // Convert string values to numbers for ICMP data
      const processedIcmp = icmp.map((row: IcmpRow) => ({
        ...row,
        ICMP_In_Echos: Number(row.ICMP_In_Echos) || 0,
        ICMP_In_Echo_Replies: Number(row.ICMP_In_Echo_Replies) || 0,
        ICMP_Out_Echos: Number(row.ICMP_Out_Echos) || 0,
        ICMP_Out_Echo_Replies: Number(row.ICMP_Out_Echo_Replies) || 0
      }));
      
      setIcmpData(processedIcmp);
      setRouteData(route);
      
      // Calculate stats for each ICMP field (filtered by selected device if set)
      const fields = ['ICMP_In_Echos', 'ICMP_In_Echo_Replies', 'ICMP_Out_Echos', 'ICMP_Out_Echo_Replies'];
      const filteredIcmp = selectedDevice && selectedDevice !== 'all' ? processedIcmp.filter((row: IcmpRow) => row.IP === selectedDevice) : processedIcmp;
      const newStats: { [key: string]: { current: number; average: string; max: number; min: number } } = {};
      
      fields.forEach((field) => {
        const values = filteredIcmp
          .map((row: IcmpRow) => {
            const val = Number(row[field as keyof IcmpRow]);
            return isNaN(val) ? 0 : val;
          })
          .filter((v: number) => v >= 0);
        
        if (values.length > 0) {
          newStats[field] = {
            current: values[values.length - 1],
            average: (values.reduce((a: number, b: number) => a + b, 0) / values.length).toFixed(2),
            max: Math.max(...values),
            min: Math.min(...values)
          };
        } else {
          newStats[field] = {
            current: 0,
            average: '0.00',
            max: 0,
            min: 0
          };
        }
      });
      
      setStats(newStats);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching data:', error);
      setLoading(false);
    }
  };

  // Recompute stats when device selection changes
  useEffect(() => {
    const fields = ['ICMP_In_Echos', 'ICMP_In_Echo_Replies', 'ICMP_Out_Echos', 'ICMP_Out_Echo_Replies'];
    const filteredIcmp = selectedDevice && selectedDevice !== 'all' ? icmpData.filter((row: IcmpRow) => row.IP === selectedDevice) : icmpData;
    const newStats: { [key: string]: { current: number; average: string; max: number; min: number } } = {};
    fields.forEach((field) => {
      const values = filteredIcmp
        .map((row: IcmpRow) => {
          const val = Number(row[field as keyof IcmpRow]);
          return isNaN(val) ? 0 : val;
        })
        .filter((v: number) => v >= 0);
      if (values.length > 0) {
        newStats[field] = {
          current: values[values.length - 1],
          average: (values.reduce((a: number, b: number) => a + b, 0) / values.length).toFixed(2),
          max: Math.max(...values),
          min: Math.min(...values)
        };
      } else {
        newStats[field] = { current: 0, average: '0.00', max: 0, min: 0 };
      }
    });
    setStats(newStats);
  }, [icmpData, selectedDevice]);

  const handleSnmpQuery = async () => {
    setQueryLoading(true);
    setQueryError(null);
    setQueryResult(null);

    try {
      const endpoint = queryType === 'get' ? '/api/snmp/get' : '/api/snmp/getnext';
      const ipParam = selectedDevice && selectedDevice !== 'all' ? `&ip=${encodeURIComponent(selectedDevice)}` : '';
      const response = await fetch(`${API_URL}${endpoint}?oid=${encodeURIComponent(queryOid)}${ipParam}`);
      
      if (!response.ok) {
        throw new Error(`Error: ${response.statusText}`);
      }

      const data = await response.json();
      
      if (data.error) {
        setQueryError(data.error);
      } else {
        setQueryResult(data);
      }
    } catch (error) {
      setQueryError(error instanceof Error ? error.message : 'Unknown error occurred');
    } finally {
      setQueryLoading(false);
    }
  };

  const StatCard = ({ title, field }: { title: string; field: string }) => {
    const stat = stats[field] || {};
    return (
      <div className="bg-white rounded-lg shadow-md p-6 border border-gray-200">
        <h3 className="text-sm font-medium text-gray-600 mb-4">{title}</h3>
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-500">Current</span>
            <span className="text-2xl font-bold text-blue-600">{stat.current || 0}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-500">Average</span>
            <span className="text-sm font-semibold text-gray-700">{stat.average || 0}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-500 flex items-center gap-1">
              <TrendingUp size={12} className="text-green-500" /> Max
            </span>
            <span className="text-sm font-semibold text-green-600">{stat.max || 0}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-500 flex items-center gap-1">
              <TrendingDown size={12} className="text-red-500" /> Min
            </span>
            <span className="text-sm font-semibold text-red-600">{stat.min || 0}</span>
          </div>
        </div>
      </div>
    );
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="text-center">
          <Activity className="animate-spin mx-auto mb-4 text-blue-600" size={48} />
          <p className="text-gray-600">Loading network data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6 border-l-4 border-blue-600">
          <div className="flex items-center gap-3">
            <Network className="text-blue-600" size={32} />
            <div>
              <h1 className="text-3xl font-bold text-gray-800">Network Management Dashboard</h1>
              <p className="text-gray-600 text-sm mt-1">Real-time SNMP Monitoring System</p>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mb-6">
          <button
            onClick={() => setActiveTab('icmp')}
            className={`px-6 py-3 rounded-lg font-medium transition-all ${
              activeTab === 'icmp'
                ? 'bg-blue-600 text-white shadow-lg'
                : 'bg-white text-gray-600 hover:bg-gray-50'
            }`}
          >
            ICMP Statistics
          </button>
          <button
            onClick={() => setActiveTab('routes')}
            className={`px-6 py-3 rounded-lg font-medium transition-all ${
              activeTab === 'routes'
                ? 'bg-blue-600 text-white shadow-lg'
                : 'bg-white text-gray-600 hover:bg-gray-50'
            }`}
          >
            IP Route Table
          </button>
          <button
            onClick={() => setActiveTab('query')}
            className={`px-6 py-3 rounded-lg font-medium transition-all ${
              activeTab === 'query'
                ? 'bg-blue-600 text-white shadow-lg'
                : 'bg-white text-gray-600 hover:bg-gray-50'
            }`}
          >
            SNMP Query Tool
          </button>
        </div>

        {activeTab === 'icmp' && (
          <>
            {/* Device Selector */}
            <div className="bg-white rounded-lg shadow-md p-4 mb-4 border border-gray-200">
              <div className="flex items-center gap-3">
                <label className="text-sm font-medium text-gray-700">Device</label>
                <select
                  value={selectedDevice}
                  onChange={(e) => setSelectedDevice(e.target.value)}
                  className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="all">All Devices</option>
                  {devices.map((d) => (
                    <option key={d.ip} value={d.ip}>{d.name} ({d.ip})</option>
                  ))}
                </select>
                {selectedDevice && selectedDevice !== 'all' && (
                  <span className="text-xs text-gray-500">IP: {selectedDevice}</span>
                )}
              </div>
            </div>
            {/* Statistics Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
              <StatCard title="ICMP In Echos" field="ICMP_In_Echos" />
              <StatCard title="ICMP In Echo Replies" field="ICMP_In_Echo_Replies" />
              <StatCard title="ICMP Out Echos" field="ICMP_Out_Echos" />
              <StatCard title="ICMP Out Echo Replies" field="ICMP_Out_Echo_Replies" />
            </div>

            {/* Graph */}
            <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
              <h2 className="text-xl font-bold text-gray-800 mb-4">ICMP Traffic Over Time</h2>
              <ResponsiveContainer width="100%" height={400}>
                <LineChart data={(selectedDevice && selectedDevice !== 'all' ? icmpData.filter((r: IcmpRow) => r.IP === selectedDevice) : icmpData).slice(-50)}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis 
                    dataKey="Timestamp" 
                    tickFormatter={(time) => new Date(time).toLocaleTimeString()}
                    tick={{ fontSize: 12 }}
                  />
                  <YAxis />
                  <Tooltip 
                    labelFormatter={(time) => new Date(time).toLocaleString()}
                  />
                  <Legend />
                  <Line type="monotone" dataKey="ICMP_In_Echos" stroke="#3b82f6" name="In Echos" strokeWidth={2} />
                  <Line type="monotone" dataKey="ICMP_In_Echo_Replies" stroke="#10b981" name="In Replies" strokeWidth={2} />
                  <Line type="monotone" dataKey="ICMP_Out_Echos" stroke="#f59e0b" name="Out Echos" strokeWidth={2} />
                  <Line type="monotone" dataKey="ICMP_Out_Echo_Replies" stroke="#ef4444" name="Out Replies" strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </div>

            {/* ICMP Table */}
            <div className="bg-white rounded-lg shadow-lg overflow-hidden">
              <div className="p-6 border-b border-gray-200">
                <h2 className="text-xl font-bold text-gray-800">ICMP Logs</h2>
                <p className="text-sm text-gray-600 mt-1">Total entries: {icmpData.length}</p>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Timestamp</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">IP</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">System Name</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Uptime</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">In Echos</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">In Replies</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Out Echos</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Out Replies</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200">
                    {(selectedDevice && selectedDevice !== 'all' ? icmpData.filter((r: IcmpRow) => r.IP === selectedDevice) : icmpData).slice(-20).reverse().map((row: IcmpRow, idx) => (
                      <tr key={idx} className="hover:bg-gray-50">
                        <td className="px-6 py-4 text-sm text-gray-900">{new Date(row.Timestamp).toLocaleString()}</td>
                        <td className="px-6 py-4 text-sm text-gray-900">{row.IP}</td>
                        <td className="px-6 py-4 text-sm text-gray-900">{row.SysName}</td>
                        <td className="px-6 py-4 text-sm text-gray-900">{row.SysUpTime}</td>
                        <td className="px-6 py-4 text-sm text-gray-900">{row.ICMP_In_Echos}</td>
                        <td className="px-6 py-4 text-sm text-gray-900">{row.ICMP_In_Echo_Replies}</td>
                        <td className="px-6 py-4 text-sm text-gray-900">{row.ICMP_Out_Echos}</td>
                        <td className="px-6 py-4 text-sm text-gray-900">{row.ICMP_Out_Echo_Replies}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}

        {activeTab === 'routes' && (
          <div className="bg-white rounded-lg shadow-lg overflow-hidden">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold text-gray-800">IP Route Table</h2>
              <div className="mt-3 flex items-center gap-3">
                <label className="text-sm font-medium text-gray-700">Device</label>
                <select
                  value={selectedDevice}
                  onChange={(e) => setSelectedDevice(e.target.value)}
                  className="px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="all">All Devices</option>
                  {devices.map((d) => (
                    <option key={d.ip} value={d.ip}>{d.name} ({d.ip})</option>
                  ))}
                </select>
                <p className="text-sm text-gray-600">Total entries: {(selectedDevice && selectedDevice !== 'all' ? routeData.filter((r: RouteRow) => r.IP === selectedDevice) : routeData).length}</p>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Timestamp</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Destination</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Mask</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Next Hop</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Interface Index</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {(selectedDevice && selectedDevice !== 'all' ? routeData.filter((r: RouteRow) => r.IP === selectedDevice) : routeData).slice(-20).reverse().map((row: RouteRow, idx) => (
                    <tr key={idx} className="hover:bg-gray-50">
                      <td className="px-6 py-4 text-sm text-gray-900">{new Date(row.Timestamp).toLocaleString()}</td>
                      <td className="px-6 py-4 text-sm text-gray-900">{row.Destination}</td>
                      <td className="px-6 py-4 text-sm text-gray-900">{row.Mask}</td>
                      <td className="px-6 py-4 text-sm text-gray-900">{row.NextHop}</td>
                      <td className="px-6 py-4 text-sm text-gray-900">{row.IfIndex}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'query' && (
          <div className="bg-white rounded-lg shadow-lg overflow-hidden">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold text-gray-800 flex items-center gap-2">
                <Network size={24} className="text-blue-600" />
                SNMP Query Tool
              </h2>
              <p className="text-sm text-gray-600 mt-1">Manual OID queries using GET and GET NEXT operations</p>
            </div>
            
            <div className="p-6">
              {/* Query Input Section */}
              <div className="bg-gray-50 rounded-lg p-6 mb-6 border border-gray-200">
                <div className="mb-4">
                  <label className="block text-sm font-medium text-gray-700 mb-2">Target Device</label>
                  <div className="flex gap-3 items-center">
                    <select
                      value={selectedDevice}
                      onChange={(e) => setSelectedDevice(e.target.value)}
                      className="w-full md:w-auto px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    >
                      <option value="all">All Devices (Query default)</option>
                      {devices.map((d) => (
                        <option key={d.ip} value={d.ip}>{d.name} ({d.ip})</option>
                      ))}
                      {devices.length === 0 && (
                        <option value="">No devices loaded</option>
                      )}
                    </select>
                    {selectedDevice && (
                      <span className="text-xs text-gray-500">IP: {selectedDevice}</span>
                    )}
                  </div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                  <div className="md:col-span-2">
                    <label className="block text-sm font-medium text-gray-700 mb-2">OID</label>
                    <input
                      type="text"
                      value={queryOid}
                      onChange={(e) => setQueryOid(e.target.value)}
                      placeholder="e.g., 1.3.6.1.2.1.1.5.0"
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-gray-500"
                    />
                    <p className="text-xs text-gray-500 mt-1">Enter the OID you want to query</p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Query Type</label>
                    <div className="flex gap-2">
                      <button
                        onClick={() => setQueryType('get')}
                        className={`flex-1 px-4 py-2 rounded-lg font-medium transition-all ${
                          queryType === 'get'
                            ? 'bg-blue-600 text-white'
                            : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                        }`}
                      >
                        GET
                      </button>
                      <button
                        onClick={() => setQueryType('getnext')}
                        className={`flex-1 px-4 py-2 rounded-lg font-medium transition-all ${
                          queryType === 'getnext'
                            ? 'bg-blue-600 text-white'
                            : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                        }`}
                      >
                        GET NEXT
                      </button>
                    </div>
                  </div>
                </div>

                <button
                  onClick={handleSnmpQuery}
                  disabled={queryLoading}
                  className="w-full md:w-auto px-6 py-2 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700 disabled:bg-gray-400 transition-all"
                >
                  {queryLoading ? 'Querying...' : 'Execute Query'}
                </button>
              </div>

              {/* Query Result Section */}
              {queryError && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
                  <p className="text-sm font-medium text-red-800">Error</p>
                  <p className="text-sm text-red-600 mt-1">{queryError}</p>
                </div>
              )}

              {queryResult && (
                <div className="bg-green-50 border border-green-200 rounded-lg p-6 mb-6">
                  <h3 className="text-lg font-bold text-green-800 mb-4">Query Result</h3>
                  <div className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">OID</label>
                      <div className="bg-white px-4 py-2 rounded-lg border border-gray-200 font-mono text-sm text-gray-900 break-all">
                        {queryResult.oid}
                      </div>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Value</label>
                      <div className="bg-white px-4 py-2 rounded-lg border border-gray-200 font-mono text-sm text-gray-900 break-all">
                        {queryResult.value}
                      </div>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">Type</label>
                      <div className="bg-white px-4 py-2 rounded-lg border border-gray-200 text-sm text-gray-900">
                        <span className="inline-block bg-blue-100 text-blue-800 px-3 py-1 rounded-full">
                          {queryResult.type}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Quick Links */}
              <div className="bg-blue-50 rounded-lg p-6 border border-blue-200">
                <h3 className="text-sm font-bold text-blue-900 mb-3">Common OIDs</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  <button
                    onClick={() => setQueryOid('1.3.6.1.2.1.1.5.0')}
                    className="text-left px-3 py-2 rounded bg-white hover:bg-blue-100 border border-blue-200 text-sm text-blue-600 font-medium transition-all"
                  >
                    sysName (1.3.6.1.2.1.1.5.0)
                  </button>
                  <button
                    onClick={() => setQueryOid('1.3.6.1.2.1.1.3.0')}
                    className="text-left px-3 py-2 rounded bg-white hover:bg-blue-100 border border-blue-200 text-sm text-blue-600 font-medium transition-all"
                  >
                    sysUpTime (1.3.6.1.2.1.1.3.0)
                  </button>
                  <button
                    onClick={() => setQueryOid('1.3.6.1.2.1.5.8.0')}
                    className="text-left px-3 py-2 rounded bg-white hover:bg-blue-100 border border-blue-200 text-sm text-blue-600 font-medium transition-all"
                  >
                    ICMP In Echos (1.3.6.1.2.1.5.8.0)
                  </button>
                  <button
                    onClick={() => setQueryOid('1.3.6.1.2.1.5.14.0')}
                    className="text-left px-3 py-2 rounded bg-white hover:bg-blue-100 border border-blue-200 text-sm text-blue-600 font-medium transition-all"
                  >
                    ICMP In Echo Replies (1.3.6.1.2.1.5.14.0)
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
