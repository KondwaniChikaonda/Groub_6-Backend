const jwt = require('jsonwebtoken');

// Middleware function to verify JWT token
function authenticateToken(req, res, next) {
    // Extract token from Authorization header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    // Verify the token
    jwt.verify(token, 'your_secret_key', (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        req.user = decoded; // Store decoded token payload in request object
        next(); // Pass control to the next middleware or route handler
    });
}

module.exports = authenticateToken;
