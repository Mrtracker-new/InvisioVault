// API Configuration
// In production, uses VITE_API_URL or defaults to the live Render backend.
// In local development, leave unset to use Vite's built-in /api proxy.
const API_URL = import.meta.env.VITE_API_URL || (import.meta.env.PROD ? 'https://invisiovault-backend.onrender.com' : '');

export default API_URL;
