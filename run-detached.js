#!/usr/bin/env node
// run-detached.js - spawn server.js as a detached background process
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';

const serverPath = path.resolve('./server.js');
const logsDir = path.resolve('./logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

const out = fs.openSync(path.join(logsDir, 'server.log'), 'a');
const err = fs.openSync(path.join(logsDir, 'server.error.log'), 'a');

const child = spawn(process.execPath, [serverPath], {
  detached: true,
  stdio: ['ignore', out, err]
});

child.unref();
console.log(`Started server in detached mode (pid: ${child.pid}); logs => ${logsDir}`);
