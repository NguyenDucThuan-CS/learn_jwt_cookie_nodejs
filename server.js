const http = require('http');
const url = require('url');
const querystring = require('querystring');
const crypto = require('crypto');

// In-memory user store (for demonstration purposes)
const users = {};

// In-memory session store
const sessions = {}; // Store session tokens and associated usernames

// Token expiration time in milliseconds (e.g., 1 hour)
const TOKEN_EXPIRATION_TIME = 60 * 60 * 1000; // 1 hour

// Generate a simple token (for demonstration purposes)
function generateToken(username) {
    const tokenData = {
        username,
        createdAt: Date.now(), // Store the creation time
    };
    return Buffer.from(JSON.stringify(tokenData)).toString('base64'); // Encode as Base64
}

// Function to hash passwords
function hashPassword(password) {
    const hash = crypto.createHash('sha256'); // Using SHA-256 for hashing
    hash.update(password);
    return hash.digest('hex'); // Return hashed password as a hexadecimal string
}

// Function to parse cookies from request headers
function parseCookies(cookieHeader) {
    const cookies = {};
    if (cookieHeader) {
        cookieHeader.split(';').forEach(cookie => {
            const [name, value] = cookie.trim().split('=');
            cookies[name] = decodeURIComponent(value);
        });
    }
    return cookies;
}

// Function to check if a token is expired
function isTokenExpired(token) {
    const decodedToken = JSON.parse(Buffer.from(token, 'base64').toString());
    const currentTime = Date.now();
    return (currentTime - decodedToken.createdAt) > TOKEN_EXPIRATION_TIME;
}

// Create the server
const server = http.createServer((req, res) => {
    const parsedUrl = url.parse(req.url);
    const method = req.method;

    // Handle sign-up
    if (parsedUrl.pathname === '/signup' && method === 'POST') {
        let body = '';

        req.on('data', chunk => {
            body += chunk.toString(); // Convert Buffer to string
        });

        req.on('end', () => {
            const { username, password } = querystring.parse(body);

            // Validate input
            if (!username || !password) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                return res.end('Username and password are required.');
            }

            // Check if username already exists
            if (users[username]) {
                res.writeHead(409, { 'Content-Type': 'text/plain' });
                return res.end('Username already exists.');
            }

            // Store new user with hashed password
            users[username] = hashPassword(password); // Hash the password before storing

            res.writeHead(201, { 'Content-Type': 'text/plain' });
            res.end(`User ${username} created successfully.`);
        });
    }

    // Handle sign-in
    else if (parsedUrl.pathname === '/signin' && method === 'POST') {
        let body = '';

        req.on('data', chunk => {
            body += chunk.toString(); // Convert Buffer to string
        });

        req.on('end', () => {
            const { username, password } = querystring.parse(body);

            if (!username || !password) {
                res.writeHead(400, { 'Content-Type': 'text/plain' });
                return res.end('Username and password are required.');
            }

            const hashedPassword = users[username];
            if (!hashedPassword || hashedPassword !== hashPassword(password)) { // Compare hashed passwords
                res.writeHead(401, { 'Content-Type': 'text/plain' });
                return res.end('Invalid credentials.');
            }

            // Create a session token for the user
            const token = generateToken(username);
            sessions[token] = username; // Store the token with associated username

            res.writeHead(200, { 'Set-Cookie': `sessionToken=${token}; HttpOnly`, 'Content-Type': 'text/plain' });
            res.end(`Welcome ${username}! Your session is active.`);
        });
    }

    // Handle protected route
    else if (parsedUrl.pathname === '/dashboard' && method === 'GET') {
        const cookies = parseCookies(req.headers.cookie);
        const token = cookies.sessionToken;

        if (!token || !sessions[token] || isTokenExpired(token)) {
            res.writeHead(401, { 'Content-Type': 'text/plain' });
            return res.end('Unauthorized access. Please log in or your session has expired.');
        }

        const username = sessions[token];
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(`Hello ${username}, welcome to your dashboard!`);
    }

    // Handle logout
    else if (parsedUrl.pathname === '/logout' && method === 'POST') {
        const cookies = parseCookies(req.headers.cookie);
        const token = cookies.sessionToken;

        if (token) {
            delete sessions[token]; // Remove the session from store
        }

        res.writeHead(200, { 'Set-Cookie': 'sessionToken=; Max-Age=0', 'Content-Type': 'text/plain' });
        res.end('Logged out successfully.');
    }

    // Handle unknown routes
    else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
});

// Start the server
const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
