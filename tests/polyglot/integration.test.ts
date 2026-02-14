import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { BundleEmitter } from '../../src/bundle-emitter.js';
import { exec } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { promisify } from 'util';

const execAsync = promisify(exec);

const isWindows = os.platform() === 'win32';
const VERIFIER_DIR = path.resolve(__dirname, '../../../guardspine-verify');
const VENV_BIN = isWindows ? 'Scripts' : 'bin';
const EXE_EXT = isWindows ? '.exe' : '';

const VERIFIER_PATH = path.join(
    VERIFIER_DIR,
    '.venv',
    VENV_BIN,
    `guardspine-verify${EXE_EXT}`
);

describe('Polyglot Integration: Node Producer -> Python Consumer', () => {
    let tempDir: string;
    let bundlePath: string;

    beforeAll(async () => {
        try {
            await fs.access(VERIFIER_PATH);
        } catch (e) {
            console.warn(`[WARN] guardspine-verify executable not found at ${VERIFIER_PATH}.`);
        }

        tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'guardspine-polyglot-'));
        bundlePath = path.join(tempDir, 'evidence.json');
    });

    afterAll(async () => {
        await fs.rm(tempDir, { recursive: true, force: true });
    });

    it('should generate a bundle in Node that verifies successfully in Python', async () => {
        // 1. Configure Emitter
        const emitter = new BundleEmitter({
            defaultRiskTier: 'low'
        });

        // 2. Create Mock Event
        const mockEvent = {
            provider: 'github',
            repo: 'test-repo',
            commit_sha: 'test-sha', // Used if sha is missing
            eventType: 'push',
            ref: 'refs/heads/main',
            sha: 'test-sha',
            author: 'test-user',
            labels: [],
            changedFiles: ['test.py'],
            diffUrl: 'https://github.com/test-repo/commit/test-sha.diff',
            rawPayload: {
                diff: 'def foo(): pass',
                author: 'test-user'
            }
        };

        // 3. Create & Seal Bundle
        // The API requires constructing a bundle from an event, then sealing it.
        const unsealed = emitter.fromEvent(mockEvent as any);
        const bundle = await emitter.sealBundle(unsealed);

        // 4. Write to disk
        await fs.writeFile(bundlePath, JSON.stringify(bundle, null, 2));

        // 5. Verify with Python
        try {
            const { stdout, stderr } = await execAsync(`"${VERIFIER_PATH}" "${bundlePath}"`);
            // console.log('Verify stdout:', stdout);
            expect(stdout).toContain('BUNDLE VERIFIED');
        } catch (error: any) {
            console.error('Verify failed:', error.stdout, error.stderr);
            throw new Error(`Verification failed: ${error.message} \nSTDOUT: ${error.stdout} \nSTDERR: ${error.stderr}`);
        }
    });

    it('should fail verification when bundle content is tampered', async () => {
        const emitter = new BundleEmitter({
            defaultRiskTier: 'critical'
        });

        const mockEvent = {
            provider: 'github',
            repo: 'test-repo-bad',
            eventType: 'push',
            sha: 'test-sha-bad',
            author: 'malicious-user',
            labels: [],
            changedFiles: ['secret.py'],
            diffUrl: 'https://github.com/bad/diff',
            rawPayload: { diff: 'SECRET="123"' }
        };

        const unsealed = emitter.fromEvent(mockEvent as any);
        const bundle = await emitter.sealBundle(unsealed);

        // Tamper with content
        const tamperedBundle = JSON.parse(JSON.stringify(bundle));

        // Find an item to tamper. The bundle has 'items' array.
        if (tamperedBundle.items && tamperedBundle.items.length > 0) {
            // Depending on how sealBundle normalizes items, content might be nested.
            // Let's check existing structure or blindly try both or check via logic.
            // In bundle-emitter.ts, items are normalized to { content: { kind..., content... } }
            // Bundle items are now normalized: { content: { content: ... } }
            // We need to tamper with the inner content to invalidate the hash
            if (tamperedBundle.items[0].content && typeof tamperedBundle.items[0].content === 'object') {
                if ('content' in tamperedBundle.items[0].content) {
                    tamperedBundle.items[0].content.content = "TAMPERED_CONTENT";
                } else {
                    // Fallback if structure is unexpected
                    tamperedBundle.items[0].content = "TAMPERED_CONTENT";
                }
            } else {
                tamperedBundle.items[0].content = "TAMPERED_CONTENT";
            }
        } else {
            throw new Error('Bundle structure unknown or empty, cannot tamper');
        }

        const tamperedPath = path.join(tempDir, 'tampered.json');
        await fs.writeFile(tamperedPath, JSON.stringify(tamperedBundle, null, 2));

        // Verify -> Expect Fail
        await expect(execAsync(`"${VERIFIER_PATH}" "${tamperedPath}"`)).rejects.toThrow();
    });
});
