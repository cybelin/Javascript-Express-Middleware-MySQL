const express = require("express");
const { v4: uuidv4 } = require("uuid");
const mysql = require("mysql2/promise");
const app = express();
const port = 3000;

// Database configuration
const dbConfig = {
    host: "localhost",
    user: "alvaro",
    password: "test1234",
    database: "CybelinServer",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
};

// Create the connection pool
const pool = mysql.createPool(dbConfig);

// Function to get the current UTC datetime
const getUtcDate = () => new Date().toISOString().slice(0, 19).replace("T", " ");

// In-memory structure to store malicious IPs
let maliciousIps = new Set();

// Time in seconds to refresh the malicious IPs
let checkIntervalInSeconds = 60;

// Function to load the interval time from the database
const loadCheckInterval = async () => {
    try {
        const [rows] = await pool.execute(
            "SELECT `Value` FROM Configurations WHERE `Key` = 'MaliciousIpCheckIntervalInSeconds' LIMIT 1"
        );
        if (rows.length > 0) {
            checkIntervalInSeconds = parseInt(rows[0].Value, 10) || 60;
        }
    } catch (error) {
        console.error("Error loading check interval:", error.message);
    }
};

// Function to load malicious IPs from the database
const loadMaliciousIps = async () => {
    try {
        const [rows] = await pool.execute(
            "SELECT IpAddress FROM BlacklistedIps WHERE IsActive = true"
        );
        maliciousIps = new Set(rows.map((row) => row.IpAddress));
        console.log("Malicious IPs updated:", maliciousIps);
    } catch (error) {
        console.error("Error loading malicious IPs:", error.message);
    }
};



// Middleware to capture request and response data
app.use(express.json());
app.use(async (req, res, next) => {
    const requestId = uuidv4(); // Generate a UUID to associate the request and response
    const requestStartTime = process.hrtime(); // Capture the start time of the request
    let responseBody = ""; // To store the response body for size calculation

    // Override res.send to capture the response body
    const originalSend = res.send.bind(res);
    res.send = (body) => {
        responseBody = typeof body === "string" ? body : JSON.stringify(body);
        return originalSend(body);
    };

    // Save request data in the database, excluding headers and body
    try {
        await pool.execute(
            `INSERT INTO RequestLogs (
        RequestId, HttpMethod, RequestPath, QueryString, ClientIp, UserAgent, RequestTime, HttpVersion
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                requestId,
                req.method,
                req.path,
                req.query ? JSON.stringify(req.query) : null,
                req.ip,
                req.headers["user-agent"] || null,
                getUtcDate(),
                req.httpVersion,
            ]
        );
    } catch (error) {
        console.error("Error storing request log:", error.message);
    }

    // Register the response when it's finished
    res.on("finish", async () => {
        const responseTime = process.hrtime(requestStartTime);
        const durationMs = responseTime[0] * 1000 + responseTime[1] / 1e6;

        try {
            await pool.execute(
                `INSERT INTO ResponseLogs (
          RequestId, StatusCode, ResponseHeaders, ResponseTime, DurationMs, ServerIp, ResponseSizeInBytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [
                    requestId,
                    res.statusCode,
                    JSON.stringify(res.getHeaders()),
                    getUtcDate(),
                    Math.round(durationMs),
                    req.hostname,
                    Buffer.byteLength(responseBody), // Calculate the size of the response body
                ]
            );
        } catch (error) {
            console.error("Error storing response log:", error.message);
        }
    });

    next();
});


// Middleware to block requests from malicious IPs
app.use((req, res, next) => {
    if (maliciousIps.has(req.ip)) {
        return res.status(403).send("Forbidden: Your IP is blocked.");
    }
    next();
});



// Test endpoint 1
app.get("/test", (req, res) => {
    res.status(200).send({ message: "Test endpoint working!" });
});

// Test endpoint 2
app.post("/test", (req, res) => {
    res.status(201).send({ message: "Post request received!", data: req.body });
});

// Server
app.listen(port, async () => {
    console.log(`Server running at http://localhost:${port}`);
    await loadCheckInterval();
    await loadMaliciousIps();
    setInterval(loadMaliciousIps, checkIntervalInSeconds * 1000);
});
