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

    if(parsedUrl.pathname === '/signup' && method === 'POST') {
        let body = '';
        req.on('data', (chunk) => {
            body += chunk.toString();
        })

        req.on('end', () => {
            const { username, password } = querystring.parse(body);

            if(!username || !password) {
                res.writeHead(400, { 'Content-type': 'text/plain' });

                return res.end('User name and password are required')
            }

            if(users[username]) {
                res.writeHead(409, { 'Content-type': 'text/plain' });
                return res.end('User name is already exist')
            }

            users[username] = hashPassword(password);
            res.writeHead(200, { 'Content-type': 'text/plain'});
            res.end(`User ${username} created successful!`)
        })
    }

    else if(parsedUrl.pathname === '/signin' && method === 'POST') {
        let body = '';

        req.on('data', (chunk) => {
            body += chunk.toString();
        })

        req.on('end', () => {
            const { username, password } = querystring.parse(body);

            if(!username || !password) {
                res.writeHead(400, {'Content-type': 'text/plain' });

                res.end('Username and password are required1')
            } 

            const expectedPassword = users[username];

            if(!expectedPassword || expectedPassword !== hashPassword(password)) {
                res.writeHead(401, {'Content-type': 'text/plain'});

                res.end('Password is not correct')
            }

            const token = generateToken(username);

            sessions[token] = username;

            res.writeHead(200, {'Set-Cookie': `sessionToken=${token}`,'Content-type': 'text/plain'});

            res.end('Sucessfully login!')
            
        })
    }

    else if(parsedUrl.pathname === '/dashboard' && req.method === 'POST') {
        const cookie =  parseCookies(req.headers.cookie);
        const token = cookie.sessionToken;

        if(!token || !sessions[token] || isTokenExpired(token)) {
            res.writeHead(401, { 'Content-type': 'text/plain' });

            res.end('Please login or session expired')
        }

        const username = sessions[token];
        res.writeHead(200, { 'Content-type': 'text/plain' });

        res.end(`Hello ${username}, welcome to dasboard!`)
    }

    else if(parsedUrl.pathname === '/logout' && req.method === 'POST') {
        const cookies =  parseCookies(req.headers.cookie);

        const token = cookies.sessionToken; 

        if(token) {
            delete sessions[token];
        }

        res.writeHead(200, { 'Content-type': 'text/plain' });

        res.end(`Logout sucessfullly!`)
    }

    else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
})

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});