import axios from 'axios';

// An empty base URL keeps local dev working through the Vite proxy (/api -> :5000),
// while a deployment can point these at a real host without touching source.
export const API_URL = import.meta.env.VITE_API_URL || '';
export const SOCKET_URL = import.meta.env.VITE_SOCKET_URL || 'http://localhost:5000';

const AUTH_PATHS = ['/login', '/register'];

export const clearSession = () => {
  localStorage.removeItem('qchat_token');
  localStorage.removeItem('qchat_user');
  sessionStorage.removeItem('qchat_last_peer');
};

const api = axios.create({ baseURL: API_URL });

api.interceptors.request.use((cfg) => {
  const token = localStorage.getItem('qchat_token');
  if (token) cfg.headers.Authorization = `Bearer ${token}`;
  return cfg;
});

/**
 * 401 means the token is missing, expired or invalid, so the session is over —
 * drop it and bounce to login. 403 ("authenticated but not allowed") is left
 * alone for callers to handle, and a failed login attempt on /login is too,
 * otherwise a wrong password would look like a session timeout.
 */
api.interceptors.response.use(
  (res) => res,
  (err) => {
    const onAuthPage = AUTH_PATHS.some(p => window.location.pathname.startsWith(p));
    if (err.response?.status === 401 && !onAuthPage) {
      clearSession();
      window.location.replace('/login');
    }
    return Promise.reject(err);
  }
);

export default api;
