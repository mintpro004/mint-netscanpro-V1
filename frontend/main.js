const { app, BrowserWindow, Menu, Tray, shell, dialog, nativeImage } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const http = require('http');
const os = require('os');

const API_PORT = 7832;
let mainWindow = null;
let tray = null;
let backendProcess = null;
let backendReady = false;

// ── BACKEND LAUNCHER ──
function getPythonCmd() {
  const platform = os.platform();
  if (platform === 'win32') return 'python';
  return 'python3';
}

function getBackendPath() {
  const devPath = path.join(__dirname, '..', 'backend', 'scanner.py');
  const prodPath = path.join(process.resourcesPath, 'backend', 'scanner.py');
  const fs = require('fs');
  return fs.existsSync(devPath) ? devPath : prodPath;
}

function startBackend() {
  const python = getPythonCmd();
  const script = getBackendPath();

  // Check if backend already running (e.g. from previous crash or manual start)
  checkBackendReady((ready) => {
    if (ready) {
      console.log('Backend already running');
      backendReady = true;
      if (mainWindow) mainWindow.loadFile(path.join(__dirname, 'public/index.html'));
      return;
    }

    console.log(`Starting backend: ${python} ${script}`);

    backendProcess = spawn(python, [script], {
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false,
    });

    backendProcess.on('error', (err) => {
      console.error('Failed to start backend:', err);
      if (mainWindow) {
        mainWindow.loadURL(`data:text/html,<body style="background:%230f1117;color:%23ef4444;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;flex-direction:column;gap:12px;text-align:center"><div style="font-size:24px;font-weight:700">Launch Error</div><div style="font-size:13px">Could not start backend scanner. Make sure <b>${python}</b> is installed and in your PATH.</div><div style="font-size:11px;color:%2364748b">${err.message}</div></body>`);
      }
    });

    backendProcess.stdout.on('data', (d) => {
      console.log('[backend]', d.toString().trim());
      if (!backendReady) {
        backendReady = true;
        if (mainWindow) mainWindow.loadFile(path.join(__dirname, 'public/index.html'));
      }
    });

    backendProcess.stderr.on('data', (d) => {
      const msg = d.toString().trim();
      console.error('[backend-err]', msg);
      if (msg.includes('running on') && !backendReady) {
        backendReady = true;
        if (mainWindow) mainWindow.loadFile(path.join(__dirname, 'public/index.html'));
      }
    });

    backendProcess.on('close', (code) => {
      console.log(`Backend exited (${code})`);
      backendReady = false;
      if (mainWindow && !mainWindow.isDestroyed() && !app.isQuitting) {
        setTimeout(() => startBackend(), 2000);
      }
    });
  });
}

function checkBackendReady(callback, attempts=0) {
  http.get(`http://127.0.0.1:${API_PORT}/api/interfaces`, (res) => {
    callback(true);
  }).on('error', () => {
    if (attempts < 20) setTimeout(() => checkBackendReady(callback, attempts+1), 500);
    else callback(false);
  });
}

// ── WINDOW ──
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1100,
    height: 750,
    minWidth: 800,
    minHeight: 560,
    title: 'NetScan Pro',
    backgroundColor: '#0f1117',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
    show: false,
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
  });

  // Show splash while loading
  mainWindow.loadURL('data:text/html,<body style="background:%230f1117;color:%23e2e8f0;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif;flex-direction:column;gap:12px"><div style="font-size:24px;font-weight:700;color:%233b82f6">NetScan Pro</div><div style="font-size:13px;color:%2364748b">Starting backend scanner...</div></body>');
  mainWindow.once('ready-to-show', () => mainWindow.show());

  mainWindow.on('closed', () => { mainWindow = null; });

  // Open external links in browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  // Build menu
  buildMenu();

  return mainWindow;
}

function buildMenu() {
  const isMac = process.platform === 'darwin';
  const template = [
    ...(isMac ? [{ label: app.name, submenu: [
      { role: 'about' }, { type: 'separator' },
      { role: 'services' }, { type: 'separator' },
      { role: 'hide' }, { role: 'hideOthers' }, { role: 'unhide' },
      { type: 'separator' }, { role: 'quit' }
    ]}] : []),
    {
      label: 'File',
      submenu: [
        { label: 'Start Scan', accelerator: 'CmdOrCtrl+R', click: () => mainWindow?.webContents.executeJavaScript('startScan()') },
        { type: 'separator' },
        isMac ? { role: 'close' } : { role: 'quit' }
      ]
    },
    {
      label: 'View',
      submenu: [
        { label: 'Devices', click: () => mainWindow?.webContents.executeJavaScript("showPane('devices')") },
        { label: 'Network Map', click: () => mainWindow?.webContents.executeJavaScript("showPane('map')") },
        { label: 'Port Scanner', click: () => mainWindow?.webContents.executeJavaScript("showPane('ports')") },
        { label: 'Vulnerabilities', click: () => mainWindow?.webContents.executeJavaScript("showPane('vulns')") },
        { label: 'Speed Test', click: () => mainWindow?.webContents.executeJavaScript("showPane('speed')") },
        { label: 'Wi-Fi', click: () => mainWindow?.webContents.executeJavaScript("showPane('wifi')") },
        { type: 'separator' },
        { role: 'reload' }, { role: 'forceReload' },
        { role: 'toggleDevTools' }, { type: 'separator' },
        { role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' },
        { type: 'separator' }, { role: 'togglefullscreen' }
      ]
    },
    {
      label: 'Help',
      submenu: [
        { label: 'GitHub Repository', click: () => shell.openExternal('https://github.com/yourusername/netscan-pro') },
        { label: 'Report Issue', click: () => shell.openExternal('https://github.com/yourusername/netscan-pro/issues') },
        { type: 'separator' },
        { label: 'About NetScan Pro', click: () => dialog.showMessageBox(mainWindow, {
          title: 'NetScan Pro',
          message: 'NetScan Pro',
          detail: `Version: ${app.getVersion()}\nPlatform: ${process.platform} ${os.arch()}\nElectron: ${process.versions.electron}\nNode.js: ${process.versions.node}`,
          buttons: ['OK']
        })}
      ]
    }
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// ── APP LIFECYCLE ──
app.whenReady().then(() => {
  createWindow();
  startBackend();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  app.isQuitting = true;
  if (backendProcess) {
    backendProcess.kill();
  }
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught:', err);
});
