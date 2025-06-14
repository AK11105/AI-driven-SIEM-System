const express = require('express');
const http = require('http');
const cors = require('cors');
const { Server } = require('socket.io');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const os = require('os');
const osUtils = require('os-utils');
const checkDiskSpace = require('check-disk-space').default;

const app = express();
const server = http.createServer(app);

// Setup Socket.IO
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// Middleware
app.use(cors());
app.use(bodyParser.json());

const mongoURI = ""; // Replace yourDatabaseName with the actual name

const connectDB = async () => {
    try {
        await mongoose.connect(mongoURI); // Mongoose defaults are now sufficient
        console.log("MongoDB connected successfully");
    } catch (error) {
        console.error("Error connecting to MongoDB:", error.message);
        process.exit(1); // Exit process if DB connection fails
    }
};

// Schema
const logSchema = new mongoose.Schema({
  log: {
    content: String,
    event_template: String,
    level: String,
    component: String,
    line_id: String
  },
  anomaly_type: String,
  severity: String,
  confidence: Number,
  anomaly_score: Number,
  processing_mode: String,
  timestamp: String // Stored as HH:MM:SS string
});

const Log = mongoose.model('Log', logSchema);

// WebSocket
io.on('connection', (socket) => {
  console.log('🔌 Frontend connected:', socket.id);
  socket.on('disconnect', () => {
    console.log('❌ Frontend disconnected:', socket.id);
  });
});

// GET logs
app.get('/api/logs', async (req, res) => {
  try {
    const logs = await Log.find().sort({ _id: -1 }).limit(100);
    res.json(logs);
  } catch (err) {
    console.error('❌ Error fetching logs:', err);
    res.status(500).send('Failed to fetch logs');
  }
});

// POST logs (accepting array from Python or other services)
app.post('/api/logs', async (req, res) => {
  const logArray = req.body;

  if (!Array.isArray(logArray)) {
    return res.status(400).send('❌ Request must be an array of logs');
  }

  try {
    const logsToInsert = logArray.map(entry => ({
      log: entry.log,
      anomaly_type: entry.anomaly_type,
      severity: entry.severity,
      confidence: entry.confidence,
      anomaly_score: entry.anomaly_score,
      processing_mode: entry.processing_mode,
      timestamp: entry.timestamp || new Date().toISOString().slice(11, 19) // fallback: HH:MM:SS
    }));

    const savedLogs = await Log.insertMany(logsToInsert);
    savedLogs.forEach(log => io.emit('new_log', log));
    console.log(`💾 Saved ${savedLogs.length} logs`);

    res.status(200).send('Logs received and broadcasted');
  } catch (err) {
    console.error('❌ Error saving logs:', err);
    res.status(500).send('Failed to save logs');
  }
});

// System Health Endpoint
app.get('/api/system-health', async (req, res) => {
  const diskPath = os.platform() === 'win32' ? 'C:\\' : '/';

  osUtils.cpuUsage(async cpuPercent => {
    const memoryFree = os.freemem();
    const memoryTotal = os.totalmem();
    const memoryUsed = memoryTotal - memoryFree;

    try {
      const disk = await checkDiskSpace(diskPath);

      const data = {
        cpu: { usage: +(cpuPercent * 100).toFixed(2) },
        memory: {
          total: memoryTotal,
          free: memoryFree,
          used: memoryUsed,
          usedPercentage: +((memoryUsed / memoryTotal) * 100).toFixed(2)
        },
        disk: {
          total: +(disk.size / (1024 ** 3)).toFixed(2),
          free: +(disk.free / (1024 ** 3)).toFixed(2),
          used: +((disk.size - disk.free) / (1024 ** 3)).toFixed(2),
          usedPercentage: +(((disk.size - disk.free) / disk.size) * 100).toFixed(2)
        },
        system: {
          hostname: os.hostname(),
          uptime: os.uptime(),
          platform: os.platform(),
          arch: os.arch(),
          cores: os.cpus().length
        }
      };

      res.json(data);
    } catch (err) {
      console.error('❌ Disk check error:', err);
      res.status(500).json({ error: 'Failed to fetch disk usage' });
    }
  });
});

connectDB();

// Start Server
server.listen(5000, () => {
  console.log('🚀 Server running at http://localhost:5000');
});
