import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { errorMessage } from "../lib/errors.js";

export function textResult(text: string): CallToolResult {
  return { content: [{ type: "text", text }] };
}

export function errorResult(message: string): CallToolResult {
  return { isError: true, content: [{ type: "text", text: `Error: ${message}` }] };
}

/**
 * Runs a tool handler and converts any thrown error into an MCP tool error,
 * so the model sees what went wrong and the server keeps running.
 */
export async function runTool(handler: () => Promise<string>): Promise<CallToolResult> {
  try {
    return textResult(await handler());
  } catch (error) {
    return errorResult(errorMessage(error));
  }
}
