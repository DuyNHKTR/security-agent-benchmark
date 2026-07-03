import { spawn } from "node:child_process";
import { createWriteStream } from "node:fs";

export interface ProcessResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export function runProcess(command: string, args: string[], options: {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  stdin?: string;
  stdoutFile?: string;
  inherit?: boolean;
} = {}): Promise<ProcessResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true
    });
    const chunks: Buffer[] = [];
    const errors: Buffer[] = [];
    const log = options.stdoutFile ? createWriteStream(options.stdoutFile) : null;
    child.stdout.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
      log?.write(chunk);
      if (options.inherit) process.stdout.write(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      errors.push(chunk);
      if (options.inherit) process.stderr.write(chunk);
    });
    child.on("error", reject);
    child.on("close", (code) => {
      log?.end();
      resolve({ exitCode: code ?? 1, stdout: Buffer.concat(chunks).toString("utf8"), stderr: Buffer.concat(errors).toString("utf8") });
    });
    if (options.stdin !== undefined) child.stdin.end(options.stdin);
    else child.stdin.end();
  });
}

export async function requireSuccess(command: string, args: string[], cwd?: string): Promise<string> {
  const result = await runProcess(command, args, { cwd });
  if (result.exitCode !== 0) throw new Error(`${command} failed: ${result.stderr.trim()}`);
  return result.stdout.trim();
}
