const request = require('supertest');
const app = require('../server');
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

// Test database connection
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'FileManager',
    password: 'newpassword',
    port: 5433
});

let authToken;
let testUserId;
let testFileId;

// Cleanup function
async function cleanup() {
    try {
        await pool.query('DELETE FROM file_metadata WHERE uploader_name = $1', ['testuser']);
        await pool.query('DELETE FROM users WHERE username = $1', ['testuser']);
    } catch (err) {
        console.error('Cleanup error:', err);
    }
}

describe('File Manager API Tests - Variant 99', () => {
    
    beforeAll(async () => {
        await cleanup();
    });

    afterAll(async () => {
        await cleanup();
        await pool.end();
    });

    describe('Authentication Tests', () => {
        
        test('Test 1: User registration', async () => {
            const response = await request(app)
                .post('/api/auth/register')
                .send({
                    username: 'testuser',
                    password: 'testpass123',
                    email: 'test@example.com'
                });

            expect(response.status).toBe(201);
            expect(response.body).toHaveProperty('token');
            expect(response.body).toHaveProperty('username', 'testuser');
            
            authToken = response.body.token;
        });

        test('Test 2: Duplicate username rejected', async () => {
            const response = await request(app)
                .post('/api/auth/register')
                .send({
                    username: 'testuser',
                    password: 'differentpass',
                    email: 'another@example.com'
                });

            expect(response.status).toBe(400);
            expect(response.body.error).toContain('already exists');
        });

        test('Test 3: User login', async () => {
            const response = await request(app)
                .post('/api/auth/login')
                .send({
                    username: 'testuser',
                    password: 'testpass123'
                });

            expect(response.status).toBe(200);
            expect(response.body).toHaveProperty('token');
            expect(response.body.username).toBe('testuser');
        });

        test('Test 4: Invalid credentials rejected', async () => {
            const response = await request(app)
                .post('/api/auth/login')
                .send({
                    username: 'testuser',
                    password: 'wrongpassword'
                });

            expect(response.status).toBe(401);
        });
    });

    describe('File Upload Tests - Variant 99', () => {
        
        test('Test 5: Upload HTML file (variant 99 viewable type)', async () => {
            const response = await request(app)
                .post('/api/files')
                .set('Authorization', `Bearer ${authToken}`)
                .attach('file', Buffer.from('<html><body>Test</body></html>'), 'test.html');

            expect(response.status).toBe(201);
            expect(response.body.name).toBe('test.html');
            expect(response.body.type).toBe('html');
            expect(response.body.uploader_name).toBe('testuser');
            
            testFileId = response.body.file_id;
        });

        test('Test 6: Upload PNG file (variant 99 viewable type)', async () => {
            const pngBuffer = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
            
            const response = await request(app)
                .post('/api/files')
                .set('Authorization', `Bearer ${authToken}`)
                .attach('file', pngBuffer, 'test.png');

            expect(response.status).toBe(201);
            expect(response.body.type).toBe('png');
        });

        test('Test 7: Accept ANY file type (variant 99)', async () => {
            const response = await request(app)
                .post('/api/files')
                .set('Authorization', `Bearer ${authToken}`)
                .attach('file', Buffer.from('console.log("test");'), 'script.js');

            expect(response.status).toBe(201);
            expect(response.body.type).toBe('js');
        });

        test('Test 8: Reject duplicate filename', async () => {
            const response = await request(app)
                .post('/api/files')
                .set('Authorization', `Bearer ${authToken}`)
                .attach('file', Buffer.from('duplicate'), 'test.html');

            expect(response.status).toBe(400);
            expect(response.body.error).toContain('already exists');
        });
    });

    describe('File Listing and Filtering Tests - Variant 99', () => {
        
        test('Test 9: List all files', async () => {
            const response = await request(app)
                .get('/api/files')
                .set('Authorization', `Bearer ${authToken}`);

            expect(response.status).toBe(200);
            expect(Array.isArray(response.body)).toBe(true);
            expect(response.body.length).toBeGreaterThan(0);
        });

        test('Test 10: Sort files by name ascending (variant 99)', async () => {
            const response = await request(app)
                .get('/api/files?ascending=true')
                .set('Authorization', `Bearer ${authToken}`);

            expect(response.status).toBe(200);
            
            // Verify sorted order
            const names = response.body.map(f => f.name);
            const sortedNames = [...names].sort();
            expect(names).toEqual(sortedNames);
        });

        test('Test 11: Sort files by name descending (variant 99)', async () => {
            const response = await request(app)
                .get('/api/files?ascending=false')
                .set('Authorization', `Bearer ${authToken}`);

            expect(response.status).toBe(200);
            
            // Verify reverse sorted order
            const names = response.body.map(f => f.name);
            const sortedNames = [...names].sort().reverse();
            expect(names).toEqual(sortedNames);
        });

        test('Test 12: Filter by HTML files (variant 99)', async () => {
            const response = await request(app)
                .get('/api/files?types=html')
                .set('Authorization', `Bearer ${authToken}`);

            expect(response.status).toBe(200);
            
            // All returned files should be HTML
            response.body.forEach(file => {
                expect(file.type).toBe('html');
            });
        });

        test('Test 13: Filter by PNG files (variant 99)', async () => {
            const response = await request(app)
                .get('/api/files?types=png')
                .set('Authorization', `Bearer ${authToken}`);

            expect(response.status).toBe(200);
            
            // All returned files should be PNG
            response.body.forEach(file => {
                expect(file.type).toBe('png');
            });
        });

        test('Test 14: Filter by multiple types - HTML and PNG (variant 99)', async () => {
            const response = await request(app)
                .get('/api/files?types=html&types=png')
                .set('Authorization', `Bearer ${authToken}`);

            expect(response.status).toBe(200);
            
            // All returned files should be either HTML or PNG
            response.body.forEach(file => {
                expect(['html', 'png']).toContain(file.type);
            });
        });
    });

    describe('File Operations Tests', () => {

        test('Test 15: Get file metadata with JSON Accept header', async () => {
            const response = await request(app)
                .get(`/api/files/${testFileId}`)
                .set('Authorization', `Bearer ${authToken}`)
                .set('Accept', 'application/json');

            expect(response.status).toBe(200);
            expect(response.body).toHaveProperty('file_id');
            expect(response.body).toHaveProperty('name');
        });

        test('Test 16: Edit file (anyone can edit in shared workspace)', async () => {
            const response = await request(app)
                .put(`/api/files/${testFileId}`)
                .set('Authorization', `Bearer ${authToken}`)
                .attach('file', Buffer.from('<html><body>Updated</body></html>'), 'test.html');

            expect(response.status).toBe(200);
            expect(response.body.editor_name).toBe('testuser');
        });

        test('Test 17: Delete non-existent file returns 404', async () => {
            const response = await request(app)
                .delete('/api/files/99999')
                .set('Authorization', `Bearer ${authToken}`);

            expect(response.status).toBe(404);
        });

        test('Test 18: Delete file (owner only)', async () => {
            const response = await request(app)
                .delete(`/api/files/${testFileId}`)
                .set('Authorization', `Bearer ${authToken}`);

            expect(response.status).toBe(204);
        });
    });

    describe('Authentication Required Tests', () => {
        
        test('Test 19: Request without token fails', async () => {
            const response = await request(app)
                .get('/api/files');

            expect(response.status).toBe(401);
        });
    });
});