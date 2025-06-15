"use client";
import { useState, useEffect, useRef } from "react";
import Navbar from './components/navbar';
import { io } from 'socket.io-client';
import { toast, ToastContainer } from "react-toastify";
import 'react-toastify/dist/ReactToastify.css';
import { Pie, Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
} from 'chart.js';

ChartJS.register(
  ArcElement, Tooltip, Legend,
  CategoryScale, LinearScale, PointElement, LineElement
);

export default function Home() {
  const [logs, setLogs] = useState([]);
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const graphRef = useRef(null);

  const threatClassifications = [
    'system_critical',
    'authentication_error',
    'file_error',
    'network_error',
    'permission_error',
    'memory error'
  ];

  useEffect(() => {
    const fetchData = async () => {
      try {
        const logsResponse = await fetch('http://localhost:5000/api/logs');
        const logsData = await logsResponse.json();
        setLogs(logsData);
        setThreats(logsData.filter(log =>
          threatClassifications.includes(log.anomaly_type)
        ));
      } catch (error) {
        console.error('Error fetching data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();

    const socket = io('http://localhost:5000');
    socket.on('new_log', (data) => {
      setLogs(prev => [data, ...prev]);
      if (threatClassifications.includes(data.anomaly_type)) {
        setThreats(prev => [data, ...prev]);
        toast.error(`New Threat: ${data.log?.content || data.content}`, {
          position: "top-right",
          theme: "dark",
          autoClose: 5000,
          pauseOnHover: true,
        });
      }
    });

    return () => socket.disconnect();
  }, []);

  const formatTimestamp = (raw) => {
    if (!raw) return 'No timestamp';
    if (raw.length < 10) {
      const today = new Date();
      return `${today.toLocaleDateString()} ${raw}`;
    }
    return new Date(raw).toLocaleString();
  };

  const threatCount = threats.length;
  const nonThreatCount = logs.length - threatCount;

  const pieData = {
    labels: [
      `Threats (${((threatCount / (logs.length || 1)) * 100).toFixed(1)}%)`,
      `Non-Threats (${((nonThreatCount / (logs.length || 1)) * 100).toFixed(1)}%)`
    ],
    datasets: [{
      data: [threatCount, nonThreatCount],
      backgroundColor: ['#ff4d4d', '#00ff9d'],
      hoverBackgroundColor: ['#ff4d4dcc', '#00ff9dcc'],
    }]
  };

  const recentLogs = logs.slice(0, 10).reverse();
  let cumulative = 0;
  const lineData = {
    labels: recentLogs.map(log =>
      formatTimestamp(log.timestamp)
    ),
    datasets: [
      {
        label: 'Logs',
        data: recentLogs.map(() => 1),
        borderColor: '#00ff9d',
        backgroundColor: '#00ff9d33',
        tension: 0.3,
      },
      {
        label: 'Threats',
        data: recentLogs.map(log =>
          threatClassifications.includes(log.anomaly_type) ? 1 : 0
        ),
        borderColor: '#ff4d4d',
        backgroundColor: '#ff4d4d33',
        tension: 0.3,
      },
      {
        label: 'Cumulative Threats',
        data: recentLogs.map(log => {
          if (threatClassifications.includes(log.anomaly_type)) cumulative++;
          return cumulative;
        }),
        borderColor: '#ff0000',
        backgroundColor: '#ff000033',
        borderDash: [5, 5],
        tension: 0.3,
      }
    ]
  };

  const scrollToGraph = () => {
    graphRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen bg-[#1a1f2c] text-gray-100">
      <ToastContainer />
      <Navbar />

      <main className="p-4 sm:p-8 max-w-7xl mx-auto">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 sm:gap-6">
          <section className="p-3 sm:p-4 border border-gray-700 rounded bg-[#2c3e50] shadow-lg col-span-1 lg:col-span-2 max-h-[350px] sm:max-h-[400px] overflow-auto">
            <div className="flex items-center justify-between mb-3 sm:mb-4">
              <h2 className="text-lg sm:text-xl text-[#00ff9d]">Recent Logs</h2>
              <button
                onClick={scrollToGraph}
                className="px-4 sm:px-6 py-1.5 sm:py-2 bg-[#00ff9d] text-[#1a1f2c] font-semibold rounded hover:bg-[#00cc7d] transition text-sm sm:text-base"
              >
                View Graph
              </button>
            </div>

            {loading ? (
              <p className="text-gray-400">Loading...</p>
            ) : logs.length === 0 ? (
              <p className="text-gray-400">No logs available</p>
            ) : (
              <ul className="space-y-3">
                {logs.slice(0, 5).map((log, idx) => {
                  const isThreat = threatClassifications.includes(log.anomaly_type);
                  console.log(log.anomaly_type);
                  
                  return (
                    <li
                      key={log._id || idx}
                      className={`p-3 rounded border ${isThreat
                        ? 'border-red-600 bg-red-900/20 text-red-100'
                        : 'border-gray-600 bg-[#1a1f2c] text-gray-300'
                        }`}
                    >
                      <p className="text-sm font-semibold">{log.log?.content || log.content || "No content"}</p>
                      <p className="text-xs italic">
                        Type: <span className="font-medium">{log.anomaly_type || "normal"}</span> |
                        Severity: <span className="text-yellow-400">{log.severity || "N/A"}</span> |
                        Confidence: <span className="text-blue-300">
                          {log.confidence != null ? `${(log.confidence * 100).toFixed(1)}%` : 'N/A'}
                        </span>
                      </p>
                      <span className="text-xs text-gray-500">{formatTimestamp(log.timestamp)}</span>
                    </li>
                  );
                })}
              </ul>
            )}
          </section>

          <section className="p-3 sm:p-4 border border-gray-700 rounded bg-[#2c3e50] shadow-lg flex flex-col items-center justify-center h-[300px] sm:h-[400px]">
            <h2 className="text-lg sm:text-xl mt-2 mb-2 text-[#00ff9d]">Threat Summary</h2>
            <div className="w-full max-w-[250px] sm:max-w-none">
              <Pie data={pieData} options={{
                maintainAspectRatio: true,
                responsive: true,
                plugins: {
                  legend: {
                    position: 'bottom',
                  }
                }
              }} />
            </div>
            <p className="mt-3 sm:mt-4 text-sm sm:text-base text-gray-400">
              Total Logs: {logs.length} | Threats: {threatCount}
            </p>
          </section>
        </div>

        <section ref={graphRef} className="mt-6 sm:mt-8 p-3 sm:p-4 border border-gray-700 rounded bg-[#2c3e50] shadow-lg max-w-4xl mx-auto">
          <h2 className="text-lg sm:text-xl mb-3 sm:mb-4 text-[#00ff9d]">Logs & Threats Over Time</h2>
          <div className="w-full">
            {recentLogs.length > 0 ? (
              <Line data={lineData} options={{
                maintainAspectRatio: true,
                responsive: true,
                scales: {
                  x: { ticks: {} },
                  y: { ticks: {} }
                },
                plugins: {
                  legend: {
                    position: 'bottom',
                  }
                }
              }} />
            ) : (
              <p className="text-center text-gray-400">No logs to visualize.</p>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
