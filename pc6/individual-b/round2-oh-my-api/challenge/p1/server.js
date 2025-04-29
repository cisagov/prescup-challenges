const express = require('express');
const { execSync } = require('child_process');

const app = express();
const ip = '0.0.0.0';
const port = 8080;
const TIMEOUT = 5000;

app.use(express.json());
app.use(express.static('static'));

app.get('/status', (req, res) => {
    try {
        const stdout = execSync(`top -b -n 1 -E k | grep "Cpu(s)\\|KiB Mem"`, { timeout : TIMEOUT }).toString();
        res.status(200).send(stdout);
    } catch (error) {
        res.status(500).send(`Error: ${error.message}`);
    }
});

app.get('/time', (req, res) => {
    try {
        const stdout = execSync(`date`, { timeout : TIMEOUT }).toString();
        res.status(200).send(stdout);
    } catch (error) {
        res.status(500).send(`Error: ${error.message}`);
    }
});

app.get('/uptime', (req, res) => {
    try {
        const stdout = execSync(`uptime`, { timeout : TIMEOUT }).toString();
        res.status(200).send(stdout);
    } catch (error) {
        res.status(500).send(`Error: ${error.message}`);
    }
});

app.get('/ping', (req, res) => {
    if (!req.query.ip) return res.status(400).send('Must provide `ip` in query');

    try {
        const stdout = execSync(`ping ${req.query.ip} -c 1`, { timeout : TIMEOUT }).toString();
        res.status(200).send(stdout);
    } catch (error) {
        res.status(500).send(`Error: ${error.message}`);
    }
});

app.listen(port, ip, () => {
    console.log(`Server is running on http://${ip}:${port}`);
});