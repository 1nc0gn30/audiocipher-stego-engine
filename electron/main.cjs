const { app, BrowserWindow, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { spawn } = require('child_process');

const IS_SMOKE = process.argv.includes('--smoke-test');
const TOOL_ID = 'audiocipher-stego-engine';
const TOOL_NAME = 'AudioCipher Stego Studio';
const BACKEND_PORT = Number(process.env.PORT || 8096);
const BACKEND_URL = `http://127.0.0.1:${BACKEND_PORT}`;

let mainWindow = null;
let backendProcess = null;
let startedByElectron = false;
const consoleErrors = [];

function isBackendRunning() {
  return new Promise((resolve) => {
    const req = http.get(`${BACKEND_URL}/health`, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.setTimeout(1200, () => {
      req.destroy();
      resolve(false);
    });
  });
}

function startBackend() {
  const rootDir = path.resolve(__dirname, '..');
  const env = { ...process.env, PORT: String(BACKEND_PORT), PYTHONUNBUFFERED: '1' };
  const pyBin = fs.existsSync('/opt/zothos-ai-env/bin/python3') ? '/opt/zothos-ai-env/bin/python3' : 'python3';
  const args = ['server.py', '--host', '127.0.0.1', '--port', String(BACKEND_PORT)];

  backendProcess = spawn(pyBin, args, {
    cwd: rootDir,
    stdio: 'ignore',
    detached: false,
    env,
  });
  startedByElectron = true;
  backendProcess.on('exit', () => {
    backendProcess = null;
  });
}

function stopBackend() {
  if (startedByElectron && backendProcess && !backendProcess.killed) {
    try {
      backendProcess.kill('SIGTERM');
    } catch (_) {}
    backendProcess = null;
    startedByElectron = false;
  }
}

async function waitForBackend(maxAttempts = 35, interval = 200) {
  for (let i = 0; i < maxAttempts; i++) {
    if (await isBackendRunning()) return true;
    await new Promise((r) => setTimeout(r, interval));
  }
  return false;
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1024,
    minHeight: 700,
    show: !IS_SMOKE,
    backgroundColor: '#08080B',
    title: `${TOOL_NAME} v2.6.0 (:${BACKEND_PORT})`,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
    autoHideMenuBar: true,
  });

  mainWindow.webContents.on('console-message', (_event, level, message) => {
    if (level >= 3 && !message.includes('favicon')) {
      consoleErrors.push(message);
    }
  });

  if (IS_SMOKE) {
    const timer = setTimeout(() => {
      stopBackend();
      console.log(JSON.stringify({ tool: TOOL_ID, port: BACKEND_PORT, ok: false, error: 'timeout' }));
      app.exit(1);
    }, 10000);

    mainWindow.webContents.once('dom-ready', async () => {
      clearTimeout(timer);
      try {
        const metrics = await mainWindow.webContents.executeJavaScript(`({
          title: document.title || '',
          textLen: (document.body && document.body.innerText ? document.body.innerText.trim().length : 0),
          htmlLen: (document.documentElement ? document.documentElement.innerHTML.length : 0),
          buttons: document.querySelectorAll('button, a, input, select, canvas').length
        })`);
        const ok = metrics.htmlLen > 100;
        console.log(JSON.stringify({
          tool: TOOL_ID,
          name: TOOL_NAME,
          port: BACKEND_PORT,
          url: BACKEND_URL,
          ok,
          ...metrics,
          consoleErrors: consoleErrors.slice(0, 5),
        }));
        stopBackend();
        app.exit(ok ? 0 : 1);
      } catch (err) {
        stopBackend();
        console.log(JSON.stringify({ tool: TOOL_ID, port: BACKEND_PORT, ok: false, error: String(err) }));
        app.exit(1);
      }
    });
  }

  mainWindow.loadURL(BACKEND_URL);

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http:') || url.startsWith('https:') || url.startsWith('solana:')) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(async () => {
  if (!(await isBackendRunning())) {
    startBackend();
    await waitForBackend();
  }
  createWindow();
});

app.on('will-quit', () => {
  stopBackend();
});

app.on('window-all-closed', () => {
  stopBackend();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
