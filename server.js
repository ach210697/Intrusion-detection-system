// backend/server.js
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const WebSocket = require('ws');
const FastSpeedtest = require('fast-speedtest-api');

const app = express();
const PORT = 6000;

app.use(cors());
app.use(express.json());

// Configure fast-speedtest-api
const speedTest = new FastSpeedtest({
    token: "YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm", // Replace with your valid token from fast.com
    verbose: false,
    timeout: 10000,
    https: true,
    urlCount: 5,
    bufferSize: 8,
    unit: FastSpeedtest.UNITS.Mbps
});

// Create a WebSocket server on port 8080
const wss = new WebSocket.Server({ port: 8080 });

wss.on('connection', (ws) => {
    console.log('Client connected');

    setInterval(async () => {
        try {
            // Get download speed in Mbps
            const downloadMbps = await speedTest.getSpeed();
            // Convert Mbps to bytes per second: 1 Mbps = 125000 Bytes/s
            const downloadBytes = downloadMbps * 125000;
            // Estimate upload speed as 70% of download speed
            const uploadBytes = downloadBytes * 0.7;

            // Build the NSL JSON object using measured speeds and static values
            const nslData = {
                "duration": 120,
                "protocol_type": "tcp",
                "service": "http",
                "flag": "SF",
                "src_bytes": Math.round(downloadBytes),
                "dst_bytes": Math.round(uploadBytes),
                "wrong_fragment": 0,
                "hot": 0,
                "logged_in": 1,
                "num_compromised": 0,
                "count": 20,
                "srv_count": 10,
                "serror_rate": 0.0,
                "srv_serror_rate": 0.0,
                "rerror_rate": 0.0,
                "srv_rerror_rate": 0.0,
                "same_srv_rate": 0.9,
                "diff_srv_rate": 0.1,
                "srv_diff_host_rate": 0.2,
                "dst_host_count": 50
            };

            // Send the NSL JSON to the Flask prediction API
            try {
                const response = await axios.post('http://127.0.0.1:5000/predict_nsl', nslData);
                nslData.prediction = response.data.prediction;
            } catch (err) {
                console.error('Prediction API error:', err.message);
                nslData.prediction = 'error';
            }

            // Send the complete JSON to the frontend via WebSocket
            ws.send(JSON.stringify(nslData));
        } catch (err) {
            console.error("Speed test error:", err.message);
        }
    }, 15000); // Repeat every 15 seconds
});

app.listen(PORT, () => {
    console.log(`Server running on http://127.0.0.1:${PORT}`);
});
