const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

/**
 * Execute a shell command with timeout
 * @param {string} command
 * @param {number} timeoutMs
 * @returns {Promise<string>}
 */
async function execCommand(command, timeoutMs = 30000) {
  try {
    const { stdout, stderr } = await execAsync(command, {
      timeout: timeoutMs,
      maxBuffer: 10 * 1024 * 1024, // 10MB
    });
    return stdout;
  } catch (err) {
    if (err.killed || err.signal === 'SIGTERM') {
      throw new Error(`Command timed out after ${timeoutMs}ms: ${command.split(' ')[0]}`);
    }
    // Some tools write results to stderr or exit with non-zero even on success
    if (err.stdout) return err.stdout;
    throw new Error(err.stderr || err.message);
  }
}

/**
 * Check if a CLI tool is available in PATH
 * @param {string} tool
 * @returns {Promise<boolean>}
 */
async function isToolAvailable(tool) {
  // Try 'where' (Windows) first, then 'which' (Unix/macOS)
  const cmd = process.platform === 'win32' ? `where ${tool}` : `which ${tool}`;
  try {
    await execAsync(cmd);
    return true;
  } catch (_) {
    // On Windows, also try 'which' in case running under WSL/Git Bash
    if (process.platform === 'win32') {
      try { await execAsync(`which ${tool}`); return true; } catch (_) {}
    }
    return false;
  }
}

module.exports = { execCommand, isToolAvailable };
