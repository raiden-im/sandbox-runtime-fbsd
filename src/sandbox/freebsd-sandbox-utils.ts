import shellquote from 'shell-quote'
import { logForDebugging } from '../utils/debug.js'
import { randomBytes } from 'node:crypto'
import * as fs from 'fs'
import { spawn, spawnSync } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  generateProxyEnvVars,
  normalizePathForSandbox,
  getMandatoryDenyWithinAllow,
} from './sandbox-utils.js'
import type {
  FsReadRestrictionConfig,
  FsWriteRestrictionConfig,
} from './sandbox-schemas.js'

export interface FreeBSDNetworkBridgeContext {
  httpSocketPath: string
  socksSocketPath: string
  httpBridgeProcess: ChildProcess
  socksBridgeProcess: ChildProcess
  httpProxyPort: number
  socksProxyPort: number
}

export interface FreeBSDSandboxParams {
  command: string
  hasNetworkRestrictions: boolean
  hasFilesystemRestrictions: boolean
  httpSocketPath?: string
  socksSocketPath?: string
  httpProxyPort?: number
  socksProxyPort?: number
  readConfig?: FsReadRestrictionConfig
  writeConfig?: FsWriteRestrictionConfig
}

// Cache for FreeBSD sandbox dependencies check
let freebsdDepsCache: boolean | undefined

/**
 * Check if FreeBSD sandbox dependencies are available (synchronous)
 * Returns true if jail, socat, and rg are installed, false otherwise
 * Cached to avoid repeated system calls
 */
export function hasFreeBSDSandboxDependenciesSync(): boolean {
  if (freebsdDepsCache !== undefined) {
    return freebsdDepsCache
  }

  try {
    // jail command is part of FreeBSD base system
    const jailResult = spawnSync('which', ['jail'], {
      stdio: 'ignore',
      timeout: 1000,
    })
    const socatResult = spawnSync('which', ['socat'], {
      stdio: 'ignore',
      timeout: 1000,
    })
    const rgResult = spawnSync('which', ['rg'], {
      stdio: 'ignore',
      timeout: 1000,
    })

    freebsdDepsCache =
      jailResult.status === 0 &&
      socatResult.status === 0 &&
      rgResult.status === 0
    return freebsdDepsCache
  } catch {
    freebsdDepsCache = false
    return false
  }
}

/**
 * Initialize the FreeBSD network bridge for sandbox networking
 *
 * ARCHITECTURE NOTE:
 * FreeBSD network sandboxing uses VNET jails which create a completely isolated
 * network stack with NO network access by default. To enable network access, we use
 * a similar approach to Linux with socat bridges:
 *
 * 1. Host side: Run socat bridges that listen on Unix sockets and forward to host proxy servers
 *    - HTTP bridge: Unix socket -> host HTTP proxy (for HTTP/HTTPS traffic)
 *    - SOCKS bridge: Unix socket -> host SOCKS5 proxy (for SSH/git traffic)
 *
 * 2. Jail side: Mount the Unix sockets into the jail and run socat listeners
 *    - HTTP listener on port 3128 -> HTTP Unix socket -> host HTTP proxy
 *    - SOCKS listener on port 1080 -> SOCKS Unix socket -> host SOCKS5 proxy
 *
 * 3. Configure environment:
 *    - HTTP_PROXY=http://localhost:3128 for HTTP/HTTPS tools
 *    - ALL_PROXY=socks5://localhost:1080 for other TCP tools
 *
 * DEPENDENCIES: Requires jail (base system) and socat (pkg install socat)
 */
export async function initializeFreeBSDNetworkBridge(
  httpProxyPort: number,
  socksProxyPort: number,
): Promise<FreeBSDNetworkBridgeContext> {
  const socketId = randomBytes(8).toString('hex')
  const httpSocketPath = join(tmpdir(), `claude-http-${socketId}.sock`)
  const socksSocketPath = join(tmpdir(), `claude-socks-${socketId}.sock`)

  // Start HTTP bridge
  const httpSocatArgs = [
    `UNIX-LISTEN:${httpSocketPath},fork,reuseaddr`,
    `TCP:localhost:${httpProxyPort},keepalive,keepidle=10,keepintvl=5,keepcnt=3`,
  ]

  logForDebugging(`Starting HTTP bridge: socat ${httpSocatArgs.join(' ')}`)

  const httpBridgeProcess = spawn('socat', httpSocatArgs, {
    stdio: 'ignore',
  })

  if (!httpBridgeProcess.pid) {
    throw new Error('Failed to start HTTP bridge process')
  }

  // Start SOCKS bridge
  const socksSocatArgs = [
    `UNIX-LISTEN:${socksSocketPath},fork,reuseaddr`,
    `TCP:localhost:${socksProxyPort},keepalive,keepidle=10,keepintvl=5,keepcnt=3`,
  ]

  logForDebugging(`Starting SOCKS bridge: socat ${socksSocatArgs.join(' ')}`)

  const socksBridgeProcess = spawn('socat', socksSocatArgs, {
    stdio: 'ignore',
  })

  if (!socksBridgeProcess.pid) {
    // Clean up HTTP bridge
    if (httpBridgeProcess.pid) {
      try {
        process.kill(httpBridgeProcess.pid, 'SIGTERM')
      } catch {
        // Ignore errors
      }
    }
    throw new Error('Failed to start SOCKS bridge process')
  }

  // Wait for both sockets to be ready
  const maxAttempts = 5
  for (let i = 0; i < maxAttempts; i++) {
    if (
      !httpBridgeProcess.pid ||
      httpBridgeProcess.killed ||
      !socksBridgeProcess.pid ||
      socksBridgeProcess.killed
    ) {
      throw new Error('FreeBSD bridge process died unexpectedly')
    }

    try {
      if (fs.existsSync(httpSocketPath) && fs.existsSync(socksSocketPath)) {
        logForDebugging(`FreeBSD bridges ready after ${i + 1} attempts`)
        break
      }
    } catch (err) {
      logForDebugging(`Error checking sockets (attempt ${i + 1}): ${err}`, {
        level: 'error',
      })
    }

    if (i === maxAttempts - 1) {
      // Clean up both processes
      if (httpBridgeProcess.pid) {
        try {
          process.kill(httpBridgeProcess.pid, 'SIGTERM')
        } catch {
          // Ignore errors
        }
      }
      if (socksBridgeProcess.pid) {
        try {
          process.kill(socksBridgeProcess.pid, 'SIGTERM')
        } catch {
          // Ignore errors
        }
      }
      throw new Error(
        `Failed to create bridge sockets after ${maxAttempts} attempts`,
      )
    }

    await new Promise(resolve => setTimeout(resolve, i * 100))
  }

  return {
    httpSocketPath,
    socksSocketPath,
    httpBridgeProcess,
    socksBridgeProcess,
    httpProxyPort,
    socksProxyPort,
  }
}

/**
 * Build the command that runs inside the jail.
 * Sets up HTTP proxy on port 3128 and SOCKS proxy on port 1080
 */
function buildJailCommand(
  httpSocketPath: string,
  socksSocketPath: string,
  userCommand: string,
): string {
  // Similar to Linux approach: start socat listeners inside jail
  const innerScript = [
    `socat TCP-LISTEN:3128,fork,reuseaddr UNIX-CONNECT:${httpSocketPath} >/dev/null 2>&1 &`,
    `socat TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:${socksSocketPath} >/dev/null 2>&1 &`,
    'trap "kill %1 %2 2>/dev/null; exit" EXIT',
    `eval ${shellquote.quote([userCommand])}`,
  ].join('\n')

  return `sh -c ${shellquote.quote([innerScript])}`
}

/**
 * Generate jail filesystem mount configuration
 * FreeBSD jails use mount_nullfs for bind mounts (similar to Linux bind mounts)
 */
async function generateJailFilesystemConfig(
  jailPath: string,
  readConfig: FsReadRestrictionConfig | undefined,
  writeConfig: FsWriteRestrictionConfig | undefined,
): Promise<{ mounts: string[]; unmounts: string[] }> {
  const mounts: string[] = []
  const unmounts: string[] = []

  // Create basic jail directory structure
  const essentialDirs = ['/dev', '/tmp', '/var/tmp', '/etc', '/usr', '/bin']
  for (const dir of essentialDirs) {
    const jailDir = join(jailPath, dir)
    if (!fs.existsSync(jailDir)) {
      fs.mkdirSync(jailDir, { recursive: true })
    }
  }

  // Mount essential directories
  // These are always needed for basic functionality
  const essentialMounts = [
    { src: '/dev', dst: join(jailPath, 'dev'), mode: 'rw' },
    { src: '/usr', dst: join(jailPath, 'usr'), mode: 'ro' },
    { src: '/bin', dst: join(jailPath, 'bin'), mode: 'ro' },
    { src: '/lib', dst: join(jailPath, 'lib'), mode: 'ro' },
    { src: '/libexec', dst: join(jailPath, 'libexec'), mode: 'ro' },
    { src: '/etc', dst: join(jailPath, 'etc'), mode: 'ro' },
  ]

  for (const mount of essentialMounts) {
    if (!fs.existsSync(mount.src)) continue

    const dstDir = mount.dst
    if (!fs.existsSync(dstDir)) {
      fs.mkdirSync(dstDir, { recursive: true })
    }

    mounts.push(`mount_nullfs ${mount.mode === 'ro' ? '-o ro' : ''} ${mount.src} ${mount.dst}`)
    unmounts.push(`umount ${mount.dst}`)
  }

  // Handle write restrictions
  if (writeConfig) {
    // With write restrictions: mount root as read-only, then allow specific paths
    const cwd = process.cwd()
    const cwdJail = join(jailPath, cwd)

    // Mount CWD and allowed write paths
    for (const pathPattern of writeConfig.allowOnly || []) {
      const normalizedPath = normalizePathForSandbox(pathPattern)

      if (normalizedPath.startsWith('/dev/')) {
        continue // Skip /dev paths, already mounted
      }

      if (!fs.existsSync(normalizedPath)) {
        logForDebugging(
          `[Sandbox FreeBSD] Skipping non-existent write path: ${normalizedPath}`,
        )
        continue
      }

      const jailMountPoint = join(jailPath, normalizedPath)
      const jailMountDir = fs.statSync(normalizedPath).isDirectory()
        ? jailMountPoint
        : join(jailMountPoint, '..')

      if (!fs.existsSync(jailMountDir)) {
        fs.mkdirSync(jailMountDir, { recursive: true })
      }

      mounts.push(`mount_nullfs ${normalizedPath} ${jailMountPoint}`)
      unmounts.push(`umount ${jailMountPoint}`)
    }

    // Handle deny within allow (make them read-only)
    const denyPaths = [
      ...(writeConfig.denyWithinAllow || []),
      ...(await getMandatoryDenyWithinAllow()),
    ]

    for (const pathPattern of denyPaths) {
      const normalizedPath = normalizePathForSandbox(pathPattern)

      if (normalizedPath.startsWith('/dev/')) continue
      if (!fs.existsSync(normalizedPath)) continue

      const jailMountPoint = join(jailPath, normalizedPath)
      const jailMountDir = fs.statSync(normalizedPath).isDirectory()
        ? jailMountPoint
        : join(jailMountPoint, '..')

      if (!fs.existsSync(jailMountDir)) {
        fs.mkdirSync(jailMountDir, { recursive: true })
      }

      // Remount as read-only
      mounts.push(`mount_nullfs -o ro ${normalizedPath} ${jailMountPoint}`)
      unmounts.push(`umount ${jailMountPoint}`)
    }
  } else {
    // No write restrictions: mount root as read-write
    const cwd = process.cwd()
    const cwdJail = join(jailPath, cwd)
    if (!fs.existsSync(cwdJail)) {
      fs.mkdirSync(cwdJail, { recursive: true })
    }
    mounts.push(`mount_nullfs ${cwd} ${cwdJail}`)
    unmounts.push(`umount ${cwdJail}`)
  }

  // Handle read restrictions using nullfs mounts to empty directories
  if (readConfig?.denyOnly) {
    for (const pathPattern of readConfig.denyOnly) {
      const normalizedPath = normalizePathForSandbox(pathPattern)

      if (!fs.existsSync(normalizedPath)) continue

      const jailMountPoint = join(jailPath, normalizedPath)
      const jailMountDir = fs.statSync(normalizedPath).isDirectory()
        ? jailMountPoint
        : join(jailMountPoint, '..')

      if (!fs.existsSync(jailMountDir)) {
        fs.mkdirSync(jailMountDir, { recursive: true })
      }

      // Mount an empty tmpfs to hide the path
      const stat = fs.statSync(normalizedPath)
      if (stat.isDirectory()) {
        mounts.push(`mount -t tmpfs tmpfs ${jailMountPoint}`)
        unmounts.push(`umount ${jailMountPoint}`)
      } else {
        // For files, create an empty file and mount it
        const emptyFile = join(tmpdir(), `empty-${randomBytes(8).toString('hex')}`)
        fs.writeFileSync(emptyFile, '')
        mounts.push(`mount_nullfs -o ro ${emptyFile} ${jailMountPoint}`)
        unmounts.push(`umount ${jailMountPoint}`)
      }
    }
  }

  return { mounts, unmounts }
}

/**
 * Wrap a command with jail-based sandbox restrictions on FreeBSD
 */
export async function wrapCommandWithSandboxFreeBSD(
  params: FreeBSDSandboxParams,
): Promise<string> {
  const {
    command,
    hasNetworkRestrictions,
    hasFilesystemRestrictions,
    httpSocketPath,
    socksSocketPath,
    httpProxyPort,
    socksProxyPort,
    readConfig,
    writeConfig,
  } = params

  // Check if we need any sandboxing
  if (!hasNetworkRestrictions && !hasFilesystemRestrictions) {
    return command
  }

  // Generate unique jail name
  const jailName = `sbx_${randomBytes(8).toString('hex')}`
  const jailPath = join(tmpdir(), jailName)

  // Create jail root directory
  if (!fs.existsSync(jailPath)) {
    fs.mkdirSync(jailPath, { recursive: true })
  }

  // Generate filesystem mounts
  const { mounts, unmounts } = await generateJailFilesystemConfig(
    jailPath,
    readConfig,
    writeConfig,
  )

  // Build jail command arguments
  const jailArgs: string[] = []

  // Basic jail parameters
  jailArgs.push('-c') // Create jail
  jailArgs.push(`name=${jailName}`)
  jailArgs.push(`path=${jailPath}`)
  jailArgs.push(`host.hostname=${jailName}`)

  // Network configuration
  if (hasNetworkRestrictions) {
    if (!httpSocketPath || !socksSocketPath) {
      throw new Error(
        'FreeBSD network sandboxing was requested but bridge socket paths are not available',
      )
    }

    // Use VNET for network isolation (requires kernel support)
    // Note: VNET requires vnet kernel option enabled
    jailArgs.push('vnet')
    jailArgs.push('allow.raw_sockets=1') // Needed for some network tools

    // Mount Unix sockets into jail for socat bridges
    const httpSocketJail = join(jailPath, httpSocketPath)
    const socksSocketJail = join(jailPath, socksSocketPath)

    const httpSocketDir = join(httpSocketJail, '..')
    const socksSocketDir = join(socksSocketJail, '..')

    if (!fs.existsSync(httpSocketDir)) {
      fs.mkdirSync(httpSocketDir, { recursive: true })
    }
    if (!fs.existsSync(socksSocketDir)) {
      fs.mkdirSync(socksSocketDir, { recursive: true })
    }

    mounts.push(`mount_nullfs ${httpSocketPath} ${httpSocketJail}`)
    mounts.push(`mount_nullfs ${socksSocketPath} ${socksSocketJail}`)
    unmounts.unshift(`umount ${httpSocketJail}`)
    unmounts.unshift(`umount ${socksSocketJail}`)
  } else {
    // Inherit host network
    jailArgs.push('ip4=inherit')
    jailArgs.push('ip6=inherit')
  }

  // Cleanup settings
  jailArgs.push('persist=0') // Auto-cleanup when last process exits
  jailArgs.push('allow.mount=0') // Prevent mounting inside jail
  jailArgs.push('allow.set_hostname=0')
  jailArgs.push('allow.sysvipc=0')

  // Build the command to run inside jail
  let jailCommand: string
  if (hasNetworkRestrictions && httpSocketPath && socksSocketPath) {
    jailCommand = buildJailCommand(httpSocketPath, socksSocketPath, command)

    // Set proxy environment variables
    const proxyEnv = generateProxyEnvVars(3128, 1080)
    for (const env of proxyEnv) {
      const firstEq = env.indexOf('=')
      const key = env.slice(0, firstEq)
      const value = env.slice(firstEq + 1)
      jailArgs.push(`env.${key}=${value}`)
    }
  } else {
    jailCommand = command
  }

  jailArgs.push(`command=sh -c '${jailCommand.replace(/'/g, "'\\''")}'`)

  // Create wrapper script that:
  // 1. Sets up mounts
  // 2. Runs jail
  // 3. Cleans up mounts and jail directory
  const setupScript = mounts.join(' && ')
  const cleanupScript = unmounts.join('; ')
  const jailCmd = shellquote.quote(['jail', ...jailArgs])

  const wrapperScript = [
    setupScript,
    jailCmd,
    `EXIT_CODE=$?`,
    cleanupScript,
    `rm -rf ${jailPath}`,
    `exit $EXIT_CODE`,
  ].join(' && ')

  const wrappedCommand = `sh -c ${shellquote.quote([wrapperScript])}`

  const restrictions = []
  if (hasNetworkRestrictions) restrictions.push('network')
  if (hasFilesystemRestrictions) restrictions.push('filesystem')

  logForDebugging(
    `[Sandbox FreeBSD] Wrapped command with jail (${restrictions.join(', ')} restrictions)`,
  )

  return wrappedCommand
}
