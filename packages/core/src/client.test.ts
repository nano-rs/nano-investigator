import { afterEach, describe, expect, it, vi } from 'vitest';

import { NanosiemClient } from './client.js';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('NanosiemClient error diagnostics', () => {
  it('preserves nano and Cloudflare correlation IDs on gateway errors', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('', {
      status: 502,
      statusText: 'Bad Gateway',
      headers: {
        'x-request-id': 'req-123',
        'cf-ray': 'ray-456-IAD',
      },
    })));

    const client = new NanosiemClient({
      apiUrl: 'https://nano.example',
      apiKey: 'test-key',
    });
    const result = await client.search({
      query: '*',
      time_range: { start: '2026-08-05T00:00:00Z', end: '2026-08-06T00:00:00Z' },
      limit: 10,
    });

    expect(result).toEqual({
      success: false,
      error: {
        code: 'HTTP_502',
        message: 'Bad Gateway (HTTP 502; request_id=req-123; cf_ray=ray-456-IAD)',
        details: {
          http_status: 502,
          request_id: 'req-123',
          cloudflare_ray: 'ray-456-IAD',
        },
      },
    });
  });

  it('keeps the sanitized server message while adding available diagnostics', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      error: { message: 'Unknown field' },
    }), {
      status: 400,
      statusText: 'Bad Request',
      headers: { 'x-request-id': 'req-789' },
    })));

    const client = new NanosiemClient({
      apiUrl: 'https://nano.example',
      apiKey: 'test-key',
    });
    const result = await client.search({
      query: 'event_name=*',
      time_range: { start: '2026-08-05T00:00:00Z', end: '2026-08-06T00:00:00Z' },
      limit: 10,
    });

    expect(result.success).toBe(false);
    expect(result.error?.message).toBe('Unknown field (HTTP 400; request_id=req-789)');
    expect(result.error?.details).toMatchObject({
      error: { message: 'Unknown field' },
      http_status: 400,
      request_id: 'req-789',
    });
  });
});
