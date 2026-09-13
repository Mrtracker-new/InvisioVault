# InvisioVault Frontend

The web client for InvisioVault, providing a secure, responsive interface for steganography, polyglot file creation, and QR code steganography. Built with React 19, Vite, and Lucide React.

## Getting Started

### Prerequisites
- Node.js (v18 or higher recommended)
- npm (v9 or higher)

### Installation
Install project dependencies:
```bash
npm install
```

### Development Server
Start the local Vite development server:
```bash
npm run dev
```
The application will be accessible at `https://localhost:5173` (HTTPS enabled via `basicSsl` for camera and QR scanner hardware permissions).

### Production Build
Build the optimized static assets:
```bash
npm run build
```

### Preview Production Build
Locally preview the production bundle:
```bash
npm run preview
```

## Architecture & Tech Stack

- **React 19**: Component-based UI library
- **Vite**: Modern frontend tooling and bundling
- **Lucide React**: Vector SVG icon system
- **Axios**: HTTP client for API communication
- **jsQR**: In-browser QR code detection and extraction
- **Vanilla CSS**: Custom design system with glassmorphic elements and dark mode variables

## Directory Structure

```
src/
├── components/
│   ├── CapacityIndicator.jsx   # Steganographic payload capacity calculations & indicators
│   ├── ExtractFile.jsx         # Steganographic data extraction interface
│   ├── HideFile.jsx            # LSB image steganography encoding interface
│   ├── Polyglot.jsx            # Multi-format polyglot creation & inspection
│   ├── QRCode.jsx              # QR code steganography generation and scanner
│   ├── TutorialModal.jsx       # Interactive user guide and documentation modal
│   └── WakeServerButton.jsx    # Backend health check and wake-up trigger
├── config/
│   └── api.js                  # API endpoint configuration
├── hooks/
│   └── useQRScanner.js         # Camera stream and QR frame decoding hook
├── App.jsx                     # Root application container and navigation
├── App.css                     # Global layout and navigation styling
├── variables.css               # Design system tokens (colors, spacing, typography)
└── main.jsx                    # Application entry point
```

## Development Guidelines

1. **Component Standards**: Keep components modular, accessible, and aligned with the CSS design system in `variables.css`.
2. **Icon Usage**: Use stroke-based icons from `lucide-react`. Maintain consistent sizing and alignment across controls.
3. **API Integration**: All backend communications should resolve through the centralized API configuration in `config/api.js`.
4. **Code Quality**: Run linting prior to committing changes:
   ```bash
   npm run lint
   ```

## Troubleshooting

- **Dependency Issues**: If dependency resolution errors occur, clear the cache and reinstall:
  ```bash
  rm -rf node_modules package-lock.json
  npm install
  ```
- **Vite Cache**: To clear the local Vite build cache:
  ```bash
  rm -rf node_modules/.vite
  ```
- **Backend Connectivity**: Ensure the InvisioVault backend is running and reachable at the configured `VITE_API_URL` or default `http://localhost:5000`.

## Additional Resources

- [React Documentation](https://react.dev)
- [Vite Documentation](https://vite.dev)
- [InvisioVault Architecture & API Documentation](../README.md)

---

## Origin Story

This was my first-ever repo. The original code was *ambitious*. I came back, learned cryptography properly, and rebuilt it from scratch. If you're a beginner: keep shipping. The rough early code is proof you're growing.

---

<p align="center">
  <strong>Built by <a href="https://rolan-rnr.netlify.app/">Rolan</a></strong><br/>
  <a href="mailto:rolanlobo901@gmail.com">rolanlobo901@gmail.com</a> · <a href="https://github.com/Mrtracker-new">GitHub</a>
</p>

<p align="center"><sub>MIT License — use it, fork it, build something weird with it.</sub></p>
