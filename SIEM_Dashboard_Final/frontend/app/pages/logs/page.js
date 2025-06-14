"use client";
import { useState, useEffect } from "react";
import Navbar from "@/app/components/navbar";
import { io } from "socket.io-client";
import { toast, ToastContainer } from "react-toastify";
import { Pie } from "react-chartjs-2";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from "chart.js";
import "react-toastify/dist/ReactToastify.css";

// Define valid threat types
const threatClassifications = [
  "system_critical",
  "memory_error",
  "authentication_error",
  "filesystem_error",
  "network_error",
  "permission_error",
];

ChartJS.register(ArcElement, Tooltip, Legend);

export default function Home() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const res = await fetch("http://localhost:5000/api/logs");
        const data = await res.json();
        setLogs(data);
        console.log(data);
      } catch (error) {
        console.error("Failed to fetch logs:", error);
      } finally {
        setLoading(false);
      }
      console.log(logs);
      
    };

    fetchLogs();

    const socket = io("http://localhost:5000");
    socket.on("new_log", (log) => {
      setLogs((prev) => [log, ...prev]);

      if (threatClassifications.includes(log.anomaly_type)) {
        toast.error(`⚠️ Threat: ${log.log.content}`, {
          position: "top-right",
          theme: "dark",
          autoClose: 5000,
          pauseOnHover: true,
        });
      }
    });

    return () => socket.disconnect();
  }, []);

  const formatTimestamp = (ts) => {
    if (!ts || ts.length <= 8) return ts; // e.g. "04:02:55"
    const date = new Date(ts);
    return isNaN(date.getTime()) ? ts : date.toLocaleString();
  };

  // Count threat occurrences for pie chart
  const threatCounts = logs.reduce((acc, log) => {
    const type = log.anomaly_type;
    if (threatClassifications.includes(type)) {
      acc[type] = (acc[type] || 0) + 1;
    }
    return acc;
  }, {});

  const pieData = {
    labels: Object.keys(threatCounts),
    datasets: [
      {
        data: Object.values(threatCounts),
        backgroundColor: [
          "#ff0066", // system_critical
          "#ff9933", // authentication_error
          "#ffcc00", // File System Error
          "#3399ff", // Network Error
          "#cc33ff", // Permission Error
          "#ff4d4d", // Memory Error
        ],
        hoverBackgroundColor: [
          "#ff3385",
          "#ffad5c",
          "#ffdb4d",
          "#66b3ff",
          "#d580ff",
          "#ff6666",
        ],
      },
    ],
  };

  const clearLogs = () => {
    setLogs([]);
    toast.success("Logs cleared!", {
      position: "bottom-left",
      theme: "dark",
    });
  };

  return (
    <div className="min-h-screen bg-[#1a1f2c] text-gray-100">
      <ToastContainer />
      <Navbar />

      <main className="p-4 sm:p-6 lg:p-8">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Threat Logs Section */}
          <section className="p-4 border border-gray-700 rounded bg-[#2c3e50] shadow-lg">
            <h2 className="text-lg sm:text-xl text-[#00ff9d] mb-4">Recent Threats</h2>
            {loading ? (
              <p className="text-gray-400">Loading...</p>
            ) : logs.filter(log => threatClassifications.includes(log.anomaly_type)).length === 0 ? (
              <p className="text-gray-400">No recent threats to display.</p>
            ) : (
              <ul className="space-y-2 max-h-[300px] overflow-auto">
                {logs
                  .filter(log_ => threatClassifications.includes(log_.anomaly_type))
                  .slice(0, 5)
                  .map((log_, idx) => (
                    <li
                      key={idx}
                      className="p-3 rounded border border-red-600 bg-red-900/20 text-red-100"
                    >
                      <p className="text-sm">{log_.log?.content ?? "No message available"}</p>

                      <div className="flex justify-between items-center mt-2 text-xs">
                        <div>
                          <p className="italic text-gray-300">
                            Type: <span className="font-medium">{log_.anomaly_type}</span>
                          </p>
                          <p className="text-gray-500">
                            {formatTimestamp(log_.timestamp)}
                          </p>
                        </div>
                        <button className="text-blue-400 hover:underline">Solution</button>
                      </div>
                    </li>
                  ))}
              </ul>
            )}
          </section>

          {/* Pie Chart Section */}
          <section className="p-4 border border-gray-700 rounded bg-[#2c3e50] shadow-lg">
            <h2 className="text-lg sm:text-xl mb-4 text-[#00ff9d]">Threat Types Distribution</h2>
            {loading ? (
              <p className="text-gray-400">Loading...</p>
            ) : Object.keys(threatCounts).length === 0 ? (
              <p className="text-gray-400">No threats detected.</p>
            ) : (
              <div className="w-full h-[280px] flex justify-center items-center">
                <Pie
                  data={pieData}
                  options={{
                    maintainAspectRatio: false,
                    responsive: true,
                    plugins: {
                      legend: {
                        position: "right",
                        labels: {
                          boxWidth: 12,
                          font: {
                            size: window.innerWidth < 768 ? 10 : 12,
                          },
                        },
                      },
                    },
                  }}
                />
              </div>
            )}
          </section>
        </div>

        {/* Buttons */}
        <div className="flex justify-between items-center mt-6">
          <button
            onClick={clearLogs}
            className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded text-sm sm:text-base"
          >
            Clear History
          </button>
          <button
            onClick={clearLogs}
            className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded text-sm sm:text-base"
          >
            Delete Logs
          </button>
        </div>
      </main>
    </div>
  );
}
