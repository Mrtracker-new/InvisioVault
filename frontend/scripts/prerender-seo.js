import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const distDir = path.resolve(__dirname, '../dist')
const publicDir = path.resolve(__dirname, '../public')

const routes = [
  {
    path: 'steganography',
    title: 'Image Steganography Online — Hide Files in Images | InvisioVault',
    description: 'Conceal confidential files and text inside PNG, JPEG, and BMP pixels using Sobel edge guidance, LSB matching (±1), and Reed-Solomon error correction.',
    canonical: 'https://invisio-vault.vercel.app/steganography',
    ogTitle: 'InvisioVault — Image Steganography Engine',
    ogDescription: 'Hide files inside images with zero visual degradation. Edge-adaptive LSB matching with authenticated Fernet encryption.',
  },
  {
    path: 'polyglot',
    title: 'Universal Polyglot File Generator — Dual-Format Carrier Files | InvisioVault',
    description: 'Create valid dual-format polyglot files. Open normally in image viewers, media players, or PDF readers; open as a ZIP archive to reveal hidden files.',
    canonical: 'https://invisio-vault.vercel.app/polyglot',
    ogTitle: 'InvisioVault — Universal Polyglot Creator',
    ogDescription: 'Hide ZIP archives inside images, PDFs, MP3s, and MP4s with automatic in-memory EOCD offset patching.',
  },
  {
    path: 'qr-code',
    title: 'Stealth QR Code Steganography & Scanner — Double-Agent Barcodes | InvisioVault',
    description: 'Generate scannable QR codes containing public data for phone cameras and encrypted secrets hidden in URL fragments (#IVDATA:). Live camera scanner included.',
    canonical: 'https://invisio-vault.vercel.app/qr-code',
    ogTitle: 'InvisioVault — Stealth QR Code Steganography',
    ogDescription: 'Double-agent QR codes: normal scanners open your public link; InvisioVault extracts the encrypted secret message.',
  },
  {
    path: 'docs',
    title: 'InvisioVault Documentation — Cryptographic Architecture & REST API',
    description: 'Technical specifications, binary wire formats (v1–v4), threat models, Sobel edge algorithms, and REST API endpoint reference for InvisioVault.',
    canonical: 'https://invisio-vault.vercel.app/docs',
    ogTitle: 'InvisioVault — Cryptography & Architecture Hub',
    ogDescription: 'Explore the complete cryptographic specifications, threat models, and OpenAPI definitions behind InvisioVault.',
  },
  {
    path: 'faq',
    title: 'InvisioVault FAQ — Steganography, Polyglots & Cryptography Answered',
    description: 'Frequently asked questions about image steganography, universal polyglot files, QR code concealment, and cryptographic zero-retention policies.',
    canonical: 'https://invisio-vault.vercel.app/faq',
    ogTitle: 'InvisioVault FAQ — Frequently Asked Questions',
    ogDescription: 'Learn how InvisioVault protects your privacy with edge-guided steganography, stateless processing, and authenticated encryption.',
  }
]

function prerender() {
  const indexPath = path.join(distDir, 'index.html')
  if (!fs.existsSync(indexPath)) {
    console.warn(`[SEO Prerender] dist/index.html not found at ${indexPath}. Run vite build first.`)
    return
  }

  const baseHtml = fs.readFileSync(indexPath, 'utf-8')
  console.log('[SEO Prerender] Generating static HTML snapshots for social crawlers and search bots...')

  const generatedPaths = new Set(['/'])

  for (const route of routes) {
    const routeDir = path.join(distDir, route.path)
    fs.mkdirSync(routeDir, { recursive: true })

    let routeHtml = baseHtml
      // Replace Title
      .replace(/<title>.*?<\/title>/, `<title>${route.title}</title>`)
      // Replace Meta Description
      .replace(/<meta name="description" content=".*?" \/>/, `<meta name="description" content="${route.description}" />`)
      // Replace Canonical
      .replace(/<link rel="canonical" href=".*?" \/>/, `<link rel="canonical" href="${route.canonical}" />`)
      // Replace Open Graph Tags
      .replace(/<meta property="og:url" content=".*?" \/>/, `<meta property="og:url" content="${route.canonical}" />`)
      .replace(/<meta property="og:title" content=".*?" \/>/, `<meta property="og:title" content="${route.ogTitle}" />`)
      .replace(/<meta property="og:description" content=".*?" \/>/, `<meta property="og:description" content="${route.ogDescription}" />`)
      // Replace Twitter Tags
      .replace(/<meta name="twitter:url" content=".*?" \/>/, `<meta name="twitter:url" content="${route.canonical}" />`)
      .replace(/<meta name="twitter:title" content=".*?" \/>/, `<meta name="twitter:title" content="${route.ogTitle}" />`)
      .replace(/<meta name="twitter:description" content=".*?" \/>/, `<meta name="twitter:description" content="${route.ogDescription}" />`)

    const outputPath = path.join(routeDir, 'index.html')
    fs.writeFileSync(outputPath, routeHtml, 'utf-8')
    generatedPaths.add(`/${route.path}`)
    console.log(`  ✓ Generated prerendered snapshot: dist/${route.path}/index.html`)
  }

  // Build-time assertion: verify every route in public/sitemap.xml has a corresponding snapshot file
  const sitemapPath = path.join(publicDir, 'sitemap.xml')
  if (fs.existsSync(sitemapPath)) {
    const sitemapContent = fs.readFileSync(sitemapPath, 'utf-8')
    const locMatches = [...sitemapContent.matchAll(/<loc>https:\/\/invisio-vault\.vercel\.app(.*?)<\/loc>/g)]
    const sitemapRoutes = locMatches.map(m => m[1] || '/')

    console.log(`[SEO Prerender] Validating sitemap coverage (${sitemapRoutes.length} URLs in sitemap.xml)...`)
    for (const smRoute of sitemapRoutes) {
      const normalized = smRoute === '' ? '/' : smRoute
      if (!generatedPaths.has(normalized)) {
        throw new Error(`[SEO Prerender Assertion Failure] Route "${normalized}" is declared in sitemap.xml but has no prerendered snapshot in dist/!`)
      }
    }
    console.log('  ✓ 100% of sitemap routes verified with pre-rendered snapshots!')
  }

  console.log('[SEO Prerender] All deep routes successfully pre-rendered for social bots & humans!')
}

prerender()
