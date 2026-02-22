export type ToolResult = {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
};

export function ok(data: unknown): ToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
}

export function err(message: string): ToolResult {
  return { content: [{ type: 'text', text: `Error: ${message}` }], isError: true };
}
