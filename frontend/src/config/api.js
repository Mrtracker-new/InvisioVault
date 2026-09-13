// API Configuration
// In production, set VITE_API_URL environment variable to your backend URL.
// In local development, leave unset to use Vite's built-in /api proxy (supports both HTTP and HTTPS).
const API_URL = import.meta.env.VITE_API_URL || '';

export default API_URL;
