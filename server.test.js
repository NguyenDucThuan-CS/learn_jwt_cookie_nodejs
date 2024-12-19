import { generateToken } from "./server";

import { describe, it, expect } from 'vitest';

describe('generate token', () => {
    it('should generate unique token when a given username', () => {
        const username = 'testuser';
        const token1 = generateToken(username);
        const token2 = generateToken(username);

        expect(typeof token1).toBe('string');

        expect(token1).not.toBe(token2);
    }),

    it('should generate a token that decodes back to the username and timestamp format', () => {
        const username = 'testuser';

        const token = generateToken(username);

        const decoded = Buffer.from(token, 'base64').toString('utf-8');

        expect(decoded.startsWith(username)).toBe(true);

        const timestamp = decoded.slice(username.length);
        expect(Number.isNaN(timestamp)).toBe(false);
    });
})


