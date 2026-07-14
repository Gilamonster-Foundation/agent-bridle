/**
 * pi-bridle — route pi's `bash` tool and `!` commands through the
 * agent-bridle capability leash.
 *
 * DRAFT / experiment, in our repo only. Not for upstream submission. See
 * README.md and newt-agent docs/decisions/lessons_from_pi.md.
 *
 * This mirrors pi's own `gondolin` example (which replaces `bash`'s operations
 * to run inside a micro-VM). Here we replace `bash`'s operations to dispatch
 * the command to the `shell` tool of an `agent-bridle-mcp` subprocess, which
 * enforces the granted Caveats before brush ever spawns the program.
 *
 * Setup:
 *   cargo build -p agent-bridle-mcp --features shell
 *   export PI_BRIDLE_MCP_BIN=/path/to/target/debug/agent-bridle-mcp
 *   export AGENT_BRIDLE_CAVEATS='{"exec":{"Only":["echo","ls","git"]}}'
 *   pi -e /path/to/agent-bridle/integrations/pi-bridle
 *
 * Requirements: an `agent-bridle-mcp` binary built with the `shell` feature.
 */

import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import type { BashOperations, ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { createBashTool } from "@earendil-works/pi-coding-agent";

const DEFAULT_MCP_BIN = "agent-bridle-mcp";

/** A successful `shell` dispatch envelope (see agent-bridle-tool-shell). */
type ShellEnvelope = {
	exit_code?: number;
	stdout?: string;
	stderr?: string;
};

/** Minimal MCP `tools/call` result shape (see agent-bridle-mcp handlers). */
type ToolCallResult = {
	content?: Array<{ type: string; text?: string }>;
	isError?: boolean;
};

/**
 * A tiny newline-delimited JSON-RPC 2.0 client over an agent-bridle-mcp
 * subprocess. Only what this extension needs: `initialize` and `tools/call`.
 */
class BridleMcp {
	private proc: ChildProcessWithoutNullStreams | undefined;
	private starting: Promise<void> | undefined;
	private nextId = 1;
	private pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
	private buffer = "";
	private banner = "";

	constructor(private readonly bin: string) {}

	async ensure(): Promise<void> {
		if (this.proc) return;
		if (!this.starting) {
			this.starting = this.start().finally(() => {
				this.starting = undefined;
			});
		}
		return this.starting;
	}

	private async start(): Promise<void> {
		const proc = spawn(this.bin, [], { stdio: ["pipe", "pipe", "pipe"] });
		this.proc = proc;

		proc.stdout.setEncoding("utf8");
		proc.stdout.on("data", (chunk: string) => this.onStdout(chunk));
		// The provenance banner (and any UNCONFINED warning) goes to stderr.
		proc.stderr.setEncoding("utf8");
		proc.stderr.on("data", (chunk: string) => {
			this.banner += chunk;
		});
		proc.on("exit", (code) => {
			const err = new Error(`agent-bridle-mcp exited (code ${code ?? "?"})`);
			for (const { reject } of this.pending.values()) reject(err);
			this.pending.clear();
			this.proc = undefined;
		});

		await this.request("initialize", {});
	}

	private onStdout(chunk: string): void {
		this.buffer += chunk;
		let newline = this.buffer.indexOf("\n");
		while (newline !== -1) {
			const line = this.buffer.slice(0, newline).trim();
			this.buffer = this.buffer.slice(newline + 1);
			if (line) this.dispatchResponse(line);
			newline = this.buffer.indexOf("\n");
		}
	}

	private dispatchResponse(line: string): void {
		let msg: { id?: number; result?: unknown; error?: { message?: string } };
		try {
			msg = JSON.parse(line);
		} catch {
			return; // ignore non-JSON noise
		}
		if (typeof msg.id !== "number") return;
		const waiter = this.pending.get(msg.id);
		if (!waiter) return;
		this.pending.delete(msg.id);
		if (msg.error) waiter.reject(new Error(msg.error.message ?? "JSON-RPC error"));
		else waiter.resolve(msg.result);
	}

	private request(method: string, params: unknown): Promise<unknown> {
		const proc = this.proc;
		if (!proc) return Promise.reject(new Error("agent-bridle-mcp not started"));
		const id = this.nextId++;
		const payload = `${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`;
		return new Promise<unknown>((resolve, reject) => {
			this.pending.set(id, { resolve, reject });
			proc.stdin.write(payload, (err) => {
				if (err) {
					this.pending.delete(id);
					reject(err);
				}
			});
		});
	}

	/** Dispatch a free-form shell command through the leashed `shell` tool. */
	async shell(cmd: string, cwd: string, timeoutSecs?: number): Promise<{ exitCode: number; stdout: string; stderr: string }> {
		const args: Record<string, unknown> = { cmd, cwd };
		if (timeoutSecs && timeoutSecs > 0) args.timeout = timeoutSecs;
		const result = (await this.request("tools/call", { name: "shell", arguments: args })) as ToolCallResult;
		const text = result.content?.map((c) => c.text ?? "").join("") ?? "";

		// A leash denial (or any tool error) comes back as isError with the
		// reason as text. Surface it as failed output, not a thrown transport
		// fault — the model should see *why* it was refused.
		if (result.isError) {
			return { exitCode: 126, stdout: "", stderr: `agent-bridle: ${text}` };
		}

		let envelope: ShellEnvelope = {};
		try {
			envelope = JSON.parse(text) as ShellEnvelope;
		} catch {
			// Non-JSON success text: treat the whole thing as stdout.
			return { exitCode: 0, stdout: text, stderr: "" };
		}
		return {
			exitCode: envelope.exit_code ?? 0,
			stdout: envelope.stdout ?? "",
			stderr: envelope.stderr ?? "",
		};
	}

	bannerText(): string {
		return this.banner.trim();
	}

	async close(): Promise<void> {
		const proc = this.proc;
		this.proc = undefined;
		if (!proc) return;
		try {
			await this.request("shutdown", {}).catch(() => undefined);
		} finally {
			proc.kill();
		}
	}
}

function createBridleBashOps(mcp: BridleMcp): BashOperations {
	return {
		exec: async (command, cwd, { onData, signal, timeout }) => {
			if (signal?.aborted) throw new Error("aborted");
			await mcp.ensure();
			const { exitCode, stdout, stderr } = await mcp.shell(command, cwd, timeout);
			if (stdout) onData(stdout);
			if (stderr) onData(stderr);
			return { exitCode };
		},
	};
}

export default function (pi: ExtensionAPI) {
	const bin = process.env.PI_BRIDLE_MCP_BIN || DEFAULT_MCP_BIN;
	const localCwd = process.cwd();
	const mcp = new BridleMcp(bin);
	const localBash = createBashTool(localCwd);

	pi.on("session_start", async (_event, ctx) => {
		try {
			await mcp.ensure();
			const banner = mcp.bannerText();
			ctx.ui.notify(`pi-bridle: shell leashed via ${bin}.${banner ? `\n${banner}` : ""}`, "info");
		} catch (error) {
			ctx.ui.notify(`pi-bridle: failed to start ${bin}: ${String(error)}`, "error");
		}
	});

	pi.on("session_shutdown", async () => {
		await mcp.close();
	});

	pi.registerCommand("bridle", {
		description: "Show the active agent-bridle leash",
		handler: async (_args, ctx) => {
			await mcp.ensure();
			ctx.ui.notify(mcp.bannerText() || "agent-bridle: leash active (no banner captured)", "info");
		},
	});

	// Replace the agent's `bash` tool: every command now runs through the leash.
	pi.registerTool({
		...localBash,
		async execute(id, params, signal, onUpdate, _ctx) {
			await mcp.ensure();
			const tool = createBashTool(localCwd, { operations: createBridleBashOps(mcp) });
			return tool.execute(id, params, signal, onUpdate);
		},
	});

	// Route the user's `!` commands through the same leash.
	pi.on("user_bash", async () => {
		await mcp.ensure();
		return { operations: createBridleBashOps(mcp) };
	});
}
