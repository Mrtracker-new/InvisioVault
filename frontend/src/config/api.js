// API Configuration
// In production (Vercel), set VITE_API_URL environment variable to your Railway backend URL
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

export default API_URL;
