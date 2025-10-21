/**
 * Platform detection utilities
 */

export type Platform = 'macos' | 'linux' | 'freebsd' | 'windows' | 'unknown'

export function getPlatform(): Platform {
  switch (process.platform) {
    case 'darwin':
      return 'macos'
    case 'linux':
      return 'linux'
    case 'freebsd':
      return 'freebsd'
    case 'win32':
      return 'windows'
    default:
      return 'unknown'
  }
}
