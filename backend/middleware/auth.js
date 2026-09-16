import jwt from 'jsonwebtoken';
import config from '../config/env.js';

/**
 * REST auth. 401 means "credentials are missing/invalid, re-authenticate" and is
 * what the frontend interceptor listens for; route handlers use 403 for
 * "authenticated, but not allowed to touch this resource".
 */
export const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  jwt.verify(token, config.jwtSecret, (err, decoded) => {
    if (err) {
      const expired = err.name === 'TokenExpiredError';
      return res.status(401).json({ error: expired ? 'Session expired' : 'Invalid token' });
    }
    req.user = decoded;
    next();
  });
};

/**
 * Socket.io handshake auth. Every socket event derives its actor from
 * socket.user rather than from the event payload, so a client can no longer
 * claim to be another user (see improve.txt SEC-5).
 */
export const authenticateSocket = (socket, next) => {
  const token = socket.handshake?.auth?.token;
  if (!token) return next(new Error('UNAUTHORIZED'));

  try {
    const decoded = jwt.verify(token, config.jwtSecret);
    if (!decoded?.id) return next(new Error('UNAUTHORIZED'));
    socket.user = { id: String(decoded.id), username: decoded.username };
    next();
  } catch (err) {
    next(new Error(err.name === 'TokenExpiredError' ? 'SESSION_EXPIRED' : 'UNAUTHORIZED'));
  }
};
