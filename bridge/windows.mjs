import { createSdkMcpServer, tool } from '@anthropic-ai/claude-agent-sdk'
import { z } from 'zod'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { homedir } from 'node:os'
import { join, extname, resolve, sep } from 'node:path'
import { mkdir, readdir, writeFile, access } from 'node:fs/promises'

const run = promisify(execFile)

/**
 * JARVIS's hands on a Windows PC.
 *
 * The Chrome bridge in chrome.mjs reaches the browser over a Unix socket, which
 * does not exist on Windows, so everyday jobs — open a site, launch an app, turn
 * the volume down, take a screenshot — have nowhere to go there. This server is
 * the Windows answer.
 *
 * It is deliberately NOT a shell. Every tool does one named thing, arguments
 * are validated, and nothing the model says is ever pasted into a command line:
 * programs are started with execFile and an argument array, and the few
 * PowerShell snippets are fixed strings whose only variable input travels in an
 * environment variable. That is what lets decideTool treat the whole server as
 * safe to run without JARVIS_ALLOW_WRITES — it can open and read and make small
 * new files, and it cannot delete, overwrite, run arbitrary programs or send.
 */

const HOME = homedir()
const text = (t) => ({ content: [{ type: 'text', text: String(t) }] })
const fail = (t) => ({ content: [{ type: 'text', text: String(t) }], isError: true })

/** Run a fixed PowerShell snippet. Variable input goes in `env`, never in `script`. */
async function ps(script, env = {}) {
  const { stdout } = await run(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
    { windowsHide: true, timeout: 20000, env: { ...process.env, ...env }, maxBuffer: 4 * 1024 * 1024 },
  )
  return stdout.trim()
}

/** Open a URL or a protocol/file target with whatever Windows has registered. */
const shellOpen = (target) =>
  run('rundll32.exe', ['url.dll,FileProtocolHandler', target], { windowsHide: true })

/**
 * Apps JARVIS may launch by name. A closed list on purpose: "open anything" is a
 * remote-code-execution hole with a friendly voice. Add your own with
 * JARVIS_APPS="name=C:\\path\\app.exe;other=ms-settings:" in the bridge shell.
 */
const APPS = {
  notepad: { exe: 'notepad.exe' },
  calculator: { uri: 'calculator:' },
  paint: { exe: 'mspaint.exe' },
  'file explorer': { exe: 'explorer.exe' },
  explorer: { exe: 'explorer.exe' },
  'task manager': { exe: 'taskmgr.exe' },
  settings: { uri: 'ms-settings:' },
  'snipping tool': { uri: 'ms-screenclip:' },
  camera: { uri: 'microsoft.windows.camera:' },
  clock: { uri: 'ms-clock:' },
  calendar: { uri: 'outlookcal:' },
  mail: { uri: 'mailto:' },
  store: { uri: 'ms-windows-store:' },
  maps: { uri: 'bingmaps:' },
  photos: { uri: 'ms-photos:' },
  'control panel': { exe: 'control.exe' },
  wordpad: { exe: 'write.exe' },
  chrome: { exe: 'chrome.exe' },
  edge: { exe: 'msedge.exe' },
  firefox: { exe: 'firefox.exe' },
  word: { exe: 'winword.exe' },
  excel: { exe: 'excel.exe' },
  powerpoint: { exe: 'powerpnt.exe' },
  outlook: { exe: 'outlook.exe' },
  vscode: { exe: 'code.cmd' },
  'visual studio code': { exe: 'code.cmd' },
  spotify: { uri: 'spotify:' },
  whatsapp: { uri: 'whatsapp:' },
  discord: { uri: 'discord:' },
  teams: { uri: 'msteams:' },
  zoom: { uri: 'zoommtg:' },
}

for (const entry of (process.env.JARVIS_APPS ?? '').split(';')) {
  const i = entry.indexOf('=')
  if (i < 1) continue
  const name = entry.slice(0, i).trim().toLowerCase()
  const target = entry.slice(i + 1).trim()
  if (name && target) APPS[name] = /^[a-z][a-z0-9+.-]*:$/i.test(target) ? { uri: target } : { exe: target }
}

const FOLDERS = {
  home: HOME,
  desktop: join(HOME, 'Desktop'),
  documents: join(HOME, 'Documents'),
  downloads: join(HOME, 'Downloads'),
  pictures: join(HOME, 'Pictures'),
  music: join(HOME, 'Music'),
  videos: join(HOME, 'Videos'),
}

/** File types that run code. Opening one of these by voice is never wanted. */
const RUNNABLE = new Set([
  '.exe', '.bat', '.cmd', '.com', '.msi', '.ps1', '.psm1', '.vbs', '.vbe', '.js',
  '.jse', '.wsf', '.wsh', '.scr', '.lnk', '.reg', '.hta', '.jar', '.dll', '.cpl',
])

/** Only paths inside the home directory, resolved, so `..` tricks fail. */
function insideHome(p) {
  const full = resolve(HOME, p)
  return full === HOME || full.toLowerCase().startsWith((HOME + sep).toLowerCase()) ? full : null
}

// Virtual-key codes for the keys we press. Sent through a fixed PowerShell
// snippet that reads the code from an environment variable.
const KEYS = {
  volume_up: 175,
  volume_down: 174,
  mute: 173,
  next_track: 176,
  previous_track: 177,
  play_pause: 179,
}
const PRESS_KEY = `
Add-Type -Namespace W -Name K -MemberDefinition '[DllImport("user32.dll")] public static extern void keybd_event(byte b, byte s, int f, int e);'
$code = [byte][int]$env:JARVIS_KEY
$n = [int]$env:JARVIS_TIMES
for ($i = 0; $i -lt $n; $i++) { [W.K]::keybd_event($code, 0, 0, 0); [W.K]::keybd_event($code, 0, 2, 0) }
`

export function windowsServer() {
  const tools = [
    tool(
      'pc_open_url',
      'Open a web page in the default browser. http and https only.',
      { url: z.string().describe('A full URL, e.g. https://chatgpt.com') },
      async ({ url }) => {
        let u
        try {
          u = new URL(/^[a-z][a-z0-9+.-]*:/i.test(url) ? url : `https://${url}`)
        } catch {
          return fail('That is not a valid URL.')
        }
        if (u.protocol !== 'https:' && u.protocol !== 'http:') return fail('Only http and https links are allowed.')
        await shellOpen(u.href)
        return text(`Opened ${u.href}`)
      },
    ),

    tool(
      'pc_web_search',
      'Search the web in the default browser (opens a Google results page).',
      { query: z.string().min(1).max(300) },
      async ({ query }) => {
        await shellOpen(`https://www.google.com/search?q=${encodeURIComponent(query)}`)
        return text(`Searching for "${query}"`)
      },
    ),

    tool(
      'pc_open_app',
      `Launch an app by name. Known: ${Object.keys(APPS).join(', ')}.`,
      { name: z.string().describe('The app name, e.g. "calculator", "notepad", "spotify"') },
      async ({ name }) => {
        const app = APPS[name.trim().toLowerCase()]
        if (!app) return fail(`I don't have "${name}" on my list. Known apps: ${Object.keys(APPS).join(', ')}.`)
        if (app.uri) await shellOpen(app.uri)
        else await run('cmd.exe', ['/c', 'start', '', app.exe], { windowsHide: true })
        return text(`Opened ${name}`)
      },
    ),

    tool(
      'pc_open_folder',
      'Open a common folder in File Explorer.',
      { folder: z.enum(Object.keys(FOLDERS)) },
      async ({ folder }) => {
        await run('explorer.exe', [FOLDERS[folder]], { windowsHide: true }).catch(() => {})
        return text(`Opened ${folder}`)
      },
    ),

    tool(
      'pc_find_files',
      'Find files by part of the name in Desktop, Documents, Downloads, Pictures, Music and Videos. Returns up to 25 paths.',
      { query: z.string().min(1).max(100) },
      async ({ query }) => {
        const needle = query.toLowerCase()
        const hits = []
        async function walk(dir, depth) {
          if (hits.length >= 25 || depth > 4) return
          let entries
          try {
            entries = await readdir(dir, { withFileTypes: true })
          } catch {
            return
          }
          for (const e of entries) {
            if (hits.length >= 25) return
            if (e.name.startsWith('.') || e.name === 'node_modules') continue
            const p = join(dir, e.name)
            if (e.name.toLowerCase().includes(needle)) hits.push(p)
            if (e.isDirectory()) await walk(p, depth + 1)
          }
        }
        for (const f of ['desktop', 'documents', 'downloads', 'pictures', 'music', 'videos']) {
          await walk(FOLDERS[f], 0)
        }
        return text(hits.length ? hits.join('\n') : `Nothing found matching "${query}".`)
      },
    ),

    tool(
      'pc_open_file',
      'Open a document, image, video or other data file in its default app. Programs and scripts are refused.',
      { path: z.string().describe('Full path, usually from pc_find_files') },
      async ({ path }) => {
        const full = insideHome(path)
        if (!full) return fail('I only open files inside your user folder.')
        if (RUNNABLE.has(extname(full).toLowerCase())) return fail('I will not launch programs or scripts by voice.')
        try {
          await access(full)
        } catch {
          return fail('That file does not exist.')
        }
        await shellOpen(full)
        return text(`Opened ${full}`)
      },
    ),

    tool(
      'pc_media',
      'Media and volume keys: play_pause, next_track, previous_track, mute, volume_up, volume_down. Each volume step is about 2%, so 5 steps is ~10%.',
      {
        action: z.enum(Object.keys(KEYS)),
        times: z.number().int().min(1).max(50).default(1),
      },
      async ({ action, times }) => {
        await ps(PRESS_KEY, { JARVIS_KEY: String(KEYS[action]), JARVIS_TIMES: String(times) })
        return text(`${action} x${times}`)
      },
    ),

    tool(
      'pc_screenshot',
      'Take a screenshot of the whole screen and save it to Pictures\\JARVIS. Returns the file path.',
      {},
      async () => {
        const dir = join(FOLDERS.pictures, 'JARVIS')
        await mkdir(dir, { recursive: true })
        const file = join(dir, `screenshot-${new Date().toISOString().replace(/[:.]/g, '-')}.png`)
        await ps(
          `Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$b = [System.Windows.Forms.SystemInformation]::VirtualScreen
$bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
$bmp.Save($env:JARVIS_FILE, [System.Drawing.Imaging.ImageFormat]::Png)`,
          { JARVIS_FILE: file },
        )
        return text(file)
      },
    ),

    tool(
      'pc_system_info',
      'Battery level, CPU load, memory and free disk space.',
      {},
      async () =>
        text(
          await ps(`$os = Get-CimInstance Win32_OperatingSystem
$cpu = (Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average
$bat = Get-CimInstance Win32_Battery
$d = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
"CPU: $cpu%"
"Memory: {0:N1} GB free of {1:N1} GB" -f ($os.FreePhysicalMemory/1MB), ($os.TotalVisibleMemorySize/1MB)
"Disk C: {0:N0} GB free of {1:N0} GB" -f ($d.FreeSpace/1GB), ($d.Size/1GB)
if ($bat) { "Battery: $($bat.EstimatedChargeRemaining)%" } else { "Battery: none (desktop)" }`),
        ),
    ),

    tool(
      'pc_clipboard',
      'Read the clipboard, or put text on it.',
      { action: z.enum(['read', 'write']), text: z.string().max(20000).optional() },
      async ({ action, text: body }) => {
        if (action === 'read') return text((await ps('Get-Clipboard -Raw')) || '(clipboard is empty)')
        if (!body) return fail('Nothing to write.')
        await ps('Set-Clipboard -Value $env:JARVIS_TEXT', { JARVIS_TEXT: body })
        return text('Copied to clipboard.')
      },
    ),

    tool(
      'pc_note',
      'Save a note as a new text file in Documents\\JARVIS Notes. Never overwrites an existing file.',
      { title: z.string().min(1).max(80), body: z.string().max(50000) },
      async ({ title, body }) => {
        const dir = join(FOLDERS.documents, 'JARVIS Notes')
        await mkdir(dir, { recursive: true })
        const safe = title.replace(/[^\w .-]/g, '').trim() || 'note'
        const file = join(dir, `${safe}-${Date.now()}.txt`)
        await writeFile(file, body, { flag: 'wx' })
        return text(`Saved ${file}`)
      },
    ),

    tool(
      'pc_show_desktop',
      'Minimise every window to show the desktop.',
      {},
      async () => {
        await ps('(New-Object -ComObject Shell.Application).MinimizeAll()')
        return text('Desktop shown.')
      },
    ),

    tool(
      'pc_lock',
      'Lock the computer. They will need their PIN or password to come back.',
      {},
      async () => {
        await run('rundll32.exe', ['user32.dll,LockWorkStation'], { windowsHide: true })
        return text('Locked.')
      },
    ),
  ]

  return createSdkMcpServer({
    name: 'jarvis_pc',
    version: '1.0.0',
    instructions:
      "The user's Windows PC. Use these for everyday jobs — opening sites and apps, " +
      'volume and media, screenshots, finding and opening files, notes, the clipboard. ' +
      'Say in one short sentence what you did.',
    alwaysLoad: true,
    tools,
  })
}
