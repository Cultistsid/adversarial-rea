#!/usr/bin/env node

/**
 * MCP Server Entry Point
 *
 * Launches the Adversarial REA MCP server for stdio communication.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema
} from '@modelcontextprotocol/sdk/types.js';
import { AdversarialMCPServer, TOOLS } from './server.js';

const server = new Server({
  name: 'adversarial-rea',
  version: '0.1.0'
}, {
  capabilities: {
    tools: {}
  }
});

const advServer = new AdversarialMCPServer();

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: advServer.getToolList()
}));

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    const result = await advServer.handleToolCall(name, args);
    return {
      content: [{
        type: 'text',
        text: JSON.stringify(result, null, 2)
      }]
    };
  } catch (error) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({ error: error.message })
      }],
      isError: true
    };
  }
});

// Start server
const transport = new StdioServerTransport();
await server.connect(transport);

console.error('Adversarial REA MCP server running');
