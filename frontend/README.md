# InvisioVault Frontend Web Client

The production web interface for InvisioVault. Engineered with React 19, Vite, React Router, and Lucide React, featuring glassmorphic dark-mode aesthetics, accessible keyboard navigation (WCAG 2.1 AA), and high-performance client-side QR frame preprocessing.

---

## 1. Getting Started

### Prerequisites
- **Node.js:** v18.0.0 or higher
- **npm:** v9.0.0 or higher

### Local Development
```bash
cd frontend
npm install
npm run dev
```
*The local development server binds to `https://localhost:5173` using `@vitejs/plugin-basic-ssl` to enable secure browser context for WebRTC camera access.*

### Production Build & Pre-rendering
```bash
npm run build
```
*Runs `vite build` and executes `node scripts/prerender-seo.js` to generate pre-rendered static HTML snapshots for deep routes (`/steganography`, `/polyglot`, `/qr-code`, `/docs`).*

### Previewing Production Build
```bash
npm run preview
```

---

## 2. Directory Structure

```
frontend/
├── public/
│   ├── .well-known/security.txt  # RFC 9116 security contact
│   ├── humans.txt                # Author and team acknowledgments
│   ├── robots.txt                # Crawler directives & search engine allowlists
│   ├── sitemap.xml               # Canonical XML sitemap with deep paths
│   └── og-image.png              # Optimized 1200x630 social preview card
├── scripts/
│   └── prerender-seo.js          # Build-time static snapshot generator for social bots
├── src/
│   ├── components/
│   │   ├── CapacityIndicator.jsx # Dynamic LSB image capacity estimation
│   │   ├── ExtractFile.jsx       # Stego extraction interface
│   │   ├── FileDropzone.jsx      # Accessible drag & drop file upload
│   │   ├── HideFile.jsx          # LSB image steganography encoding interface
│   │   ├── Polyglot.jsx          # Universal polyglot creation and inspection
│   │   ├── ProcessingIndicator.jsx # Processing animations & progress states
│   │   ├── QRCode.jsx            # Double-agent QR generation & camera scanner
│   │   ├── SeoContent.jsx        # Crawlable specs, FAQ accordion & warnings
│   │   ├── StepProgress.jsx      # Multi-step progress visualizer
│   │   ├── TutorialModal.jsx     # In-app guide and tutorial modal
│   │   └── WakeServerButton.jsx  # Render backend health check & wake trigger
│   ├── config/
│   │   └── api.js                # Centralized backend endpoint configuration
│   ├── hooks/
│   │   └── useQRScanner.js       # Real-time WebRTC camera frame capture & jsQR loop
│   ├── utils/
│   │   └── apiError.js           # Safe client-side API error handling
│   ├── App.jsx                   # Deep route manager & dynamic SEO metadata
│   ├── App.css                   # Global layout styling
│   ├── variables.css             # Design tokens (colors, typography, radii)
│   └── main.jsx                  # React 19 entry point with BrowserRouter
├── middleware.js                 # Vercel Edge Middleware for social bot redirection
└── vercel.json                   # Vercel production headers and security rules
```

---

## 3. Deep Routing & SEO Architecture

InvisioVault uses **React Router** to map functional modes to clean, indexable URL paths:

| Route Path | Tool View | Dynamic Document Title |
|---|---|---|
| `/` or `/steganography` | Image Steganography | `InvisioVault — Image Steganography Online` |
| `/polyglot` | Universal Polyglot | `InvisioVault — Universal Polyglot File Generator` |
| `/qr-code` | Stealth QR Code | `InvisioVault — Stealth QR Code Steganography & Scanner` |
| `/docs` | Documentation Hub | `InvisioVault — Cryptographic Documentation & Architecture` |

### Social Crawler Handling (Open Graph / Twitter Cards)
Because client-side rendered apps update document `<head>` after Javascript execution, social crawlers (Twitter/X, Facebook, LinkedIn, Discord, Slack) do not execute React scripts:
1. **Static Route Snapshots:** During `npm run build`, `scripts/prerender-seo.js` generates static HTML snapshots for `/steganography/index.html`, `/polyglot/index.html`, etc. with baked-in `<title>`, `<meta name="description">`, and `og:image` tags.
2. **Vercel Edge Middleware (`middleware.js`):** Intercepts social scraper user agents and routes them directly to the pre-rendered HTML snapshot.

---

## 4. Design System & Accessibility Standards

- **Tokens:** All components consume CSS variables declared in `variables.css`.
- **Keyboard Navigation (WCAG 2.1 AA):** All tabs implement WAI-ARIA tablist patterns with ArrowLeft/ArrowRight keyboard cycling, Skip to Main Content links, and high-contrast visible focus rings.
- **Hardware Permissions:** Camera access is gated behind explicit user action and handled with graceful error boundaries if device permissions are denied.
