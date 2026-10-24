/**
 * The safety net for full-access mode (JARVIS_ACCESS=full).
 *
 * Full access means JARVIS may run commands, write files anywhere and use every
 * connected tool without being stopped for each one. Two things still deserve a
 * brake, because a voice assistant mishears and because pages, emails and files
 * it reads can contain text written to steer it:
 *
 *   block   — never, even if the user says yes out loud. Reading the places where
 *             passwords and tokens live is how an injected instruction would steal
 *             them, and there is no spoken sentence that makes that sensible.
 *   confirm — runs only after the user has said yes to this specific action in
 *             their own words. Deleting, formatting, shutting down, changing
 *             system or security settings, writing into Windows or Program Files,
 *             and anything that sends, pays, posts or publishes.
 *   ok      — everything else just runs.
 */

/** Places credentials live. Matched against paths and command text. */
const SECRET_PATHS = [
  /\.ssh[\\/]/i,
  /\.aws[\\/]/i,
  /\.azure[\\/]/i,
  /\.kube[\\/]/i,
  /\.gnupg[\\/]/i,
  /\.claude[\\/]\.credentials/i,
  /\.claude\.json/i,
  /\.git-credentials/i,
  /\.npmrc/i,
  /\.netrc/i,
  /\.env(\.local|\.production)?\b/i,
  /Login Data/i,
  /Web Data/i,
  /Local State/i,
  /Cookies\b/i,
  /User Data[\\/].*(Default|Profile)/i,
  /Microsoft[\\/]Credentials/i,
  /Microsoft[\\/]Protect/i,
  /\bSAM\b.*\bSYSTEM\b/i,
  /\bwallet\.dat\b/i,
  /id_(rsa|ed25519|ecdsa)/i,
]

/** Shell commands that cannot be undone, or that change the system's security. */
const RISKY_COMMAND = new RegExp(
  [
    String.raw`\brm\s+(-[a-z]*[rf][a-z]*\s+)?\S`,
    String.raw`\b(del|erase|rmdir|rd)\s+\S`,
    String.raw`\bRemove-Item\b`,
    String.raw`\bClear-(Disk|RecycleBin|EventLog)\b`,
    String.raw`\bformat(\.com)?\s+[a-z]:`,
    String.raw`\b(diskpart|cipher\s+/w|sdelete|bcdedit)\b`,
    String.raw`\b(shutdown|Restart-Computer|Stop-Computer|logoff)\b`,
    String.raw`\breg(\.exe)?\s+(delete|add|import|load)\b`,
    String.raw`\b(Set|New|Remove)-ItemProperty\b.*HK(LM|CU)`,
    String.raw`\bSet-ExecutionPolicy\b`,
    String.raw`\bSet-MpPreference\b|\bAdd-MpPreference\b|\bDisable-(NetFirewallRule|WindowsOptionalFeature)\b`,
    String.raw`\bnetsh\b|\bnet(1)?\s+(user|localgroup|accounts)\b`,
    String.raw`\b(takeown|icacls|cacls)\b`,
    String.raw`\b(schtasks|sc(\.exe)?\s+(create|config|delete)|New-Service|Remove-Service)\b`,
    String.raw`\bgit\s+(push\s+.*(--force|-f\b)|reset\s+--hard|clean\s+-[a-z]*f)`,
    String.raw`\b(curl|wget|iwr|Invoke-WebRequest|irm|Invoke-RestMethod)\b.*(\||;)\s*(sh|bash|iex|Invoke-Expression|powershell|cmd)`,
    String.raw`\b(Invoke-Expression|iex)\b`,
    String.raw`\b(winget|choco|scoop|pip|npm)\s+(install|i|uninstall|remove)\b`,
    String.raw`\bStart-Process\b.*-Verb\s+RunAs`,
    String.raw`\bTaskkill\b|\bStop-Process\b`,
    String.raw`\bMove-Item\b.*\\(Windows|Program Files)`,
  ].join('|'),
  'i',
)

/** MCP tool names that send, spend, publish or destroy. */
const RISKY_MCP = /(delete|trash|remove|send|forward|pay|purchase|buy|charge|checkout|publish|post|tweet|deploy|transfer|cancel|unsubscribe|revoke|reset|drop|wipe|terminate|call)/i

const SYSTEM_DIRS = /^[a-z]:[\\/](Windows|Program Files( \(x86\))?|ProgramData)[\\/]/i

const COMMAND_TOOLS = new Set(['Bash', 'PowerShell'])
const FILE_WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit'])

const text = (v) => (typeof v === 'string' ? v : v == null ? '' : JSON.stringify(v))

/**
 * @returns {{ verdict: 'ok' | 'confirm' | 'block', why: string }}
 */
export function classify(toolName, input = {}) {
  const everything = text(input)

  // Reading or touching secrets is refused outright, whatever tool is asked.
  if (SECRET_PATHS.some((re) => re.test(everything))) {
    return { verdict: 'block', why: 'it touches a place where passwords or tokens are stored' }
  }

  if (COMMAND_TOOLS.has(toolName)) {
    const cmd = text(input.command)
    if (RISKY_COMMAND.test(cmd)) {
      return { verdict: 'confirm', why: 'it runs a command that can delete things, install software or change system settings' }
    }
    return { verdict: 'ok', why: '' }
  }

  if (FILE_WRITE_TOOLS.has(toolName)) {
    if (SYSTEM_DIRS.test(text(input.file_path ?? input.notebook_path))) {
      return { verdict: 'confirm', why: 'it writes inside the Windows or Program Files folders' }
    }
    return { verdict: 'ok', why: '' }
  }

  if (toolName.startsWith('mcp__')) {
    const parts = toolName.split('__')
    const server = parts[1]
    const tool = parts.slice(2).join('__')
    // The PC tools have their own checks (pc_send_email demands confirm itself).
    if (server === 'jarvis' || server === 'jarvis_ui' || server === 'jarvis_eyes') return { verdict: 'ok', why: '' }
    if (server === 'jarvis_pc') {
      return tool === 'pc_send_email'
        ? { verdict: 'confirm', why: 'it sends an email' }
        : { verdict: 'ok', why: '' }
    }
    if (RISKY_MCP.test(tool)) {
      return { verdict: 'confirm', why: `${tool.replace(/_/g, ' ')} cannot easily be undone or leaves your machine` }
    }
  }

  return { verdict: 'ok', why: '' }
}

const YES = /^\s*(yes|yeah|yep|yup|sure|confirm(ed)?|do it|go ahead|proceed|please do|okay|ok|affirmative|approved?)\b/i
const NO = /^\s*(no|nope|don'?t|stop|cancel|abort|never ?mind|negative)\b/i

export const isYes = (s) => YES.test(s)
export const isNo = (s) => NO.test(s)
