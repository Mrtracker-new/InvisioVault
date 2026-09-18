import { useState, useEffect, lazy, Suspense } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { HelpCircle, Shield, Image as ImageIcon, Layers, QrCode } from 'lucide-react'
import WakeServerButton from './components/WakeServerButton'
import SeoContent from './components/SeoContent'
import './App.css'

// Dynamic Code Splitting per tool mode for optimal LCP & bundle performance
const HideFile = lazy(() => import('./components/HideFile'))
const ExtractFile = lazy(() => import('./components/ExtractFile'))
const Polyglot = lazy(() => import('./components/Polyglot'))
const QRCode = lazy(() => import('./components/QRCode'))
const TutorialModal = lazy(() => import('./components/TutorialModal'))

const ROUTE_METADATA = {
  stego: {
    path: '/steganography',
    title: 'InvisioVault — Image Steganography Online',
    description: 'Conceal files inside PNG, JPEG, and BMP pixels using Sobel edge guidance, LSB-matching (±1), and Reed-Solomon error correction.',
  },
  polyglot: {
    path: '/polyglot',
    title: 'InvisioVault — Universal Polyglot File Generator',
    description: 'Create dual-format carrier files with in-memory ZIP EOCD offset patching. Valid in image viewers and archive managers.',
  },
  qrcode: {
    path: '/qr-code',
    title: 'InvisioVault — Stealth QR Code Steganography & Scanner',
    description: 'Generate stealth QR codes with hidden encrypted payloads via visual module steganography and scan them in real time with your webcam.',
  },
  docs: {
    path: '/docs',
    title: 'InvisioVault — Cryptographic Documentation & Architecture',
    description: 'Explore the technical specifications, binary wire formats (v1–v4), threat models, and REST API reference behind InvisioVault.',
  },
  faq: {
    path: '/faq',
    title: 'InvisioVault FAQ — Steganography & Polyglot Questions Answered',
    description: 'Frequently asked questions about image steganography, universal polyglot files, QR code concealment, and cryptographic zero-retention policies.',
  }
}

function ComponentLoader() {
  return (
    <div className="content-suspense-loading" role="status" aria-live="polite">
      <div className="suspense-spinner" aria-hidden="true"></div>
      <p>Initializing cryptographic module...</p>
    </div>
  )
}

function App() {
  const location = useLocation()
  const navigate = useNavigate()

  // Determine initial mode from URL pathname
  const getModeFromPath = (pathname) => {
    const clean = pathname.replace(/\/$/, '')
    if (clean === '/polyglot') return 'polyglot'
    if (clean === '/qr-code' || clean === '/qrcode') return 'qrcode'
    if (clean === '/docs' || clean === '/faq') return 'stego'
    return 'stego'
  }

  const [mode, setMode] = useState(() => getModeFromPath(location.pathname))
  const [activeTab, setActiveTab] = useState('hide')
  const [showTutorial, setShowTutorial] = useState(() => location.pathname.replace(/\/$/, '') === '/docs')

  // Sync mode with pathname changes and update document SEO metadata
  useEffect(() => {
    const clean = location.pathname.replace(/\/$/, '')
    let currentModeKey = 'stego'

    if (clean === '/polyglot') {
      currentModeKey = 'polyglot'
      setMode('polyglot')
    } else if (clean === '/qr-code' || clean === '/qrcode') {
      currentModeKey = 'qrcode'
      setMode('qrcode')
    } else if (clean === '/docs') {
      currentModeKey = 'docs'
      setShowTutorial(true)
    } else if (clean === '/faq') {
      currentModeKey = 'faq'
      setMode('stego')
      // Smooth scroll to FAQ section
      setTimeout(() => {
        document.querySelector('.faq-container')?.scrollIntoView({ behavior: 'smooth' })
      }, 100)
    } else {
      currentModeKey = 'stego'
      setMode('stego')
    }

    // Dynamic SEO Head Updates for Client-Side Navigation
    const meta = ROUTE_METADATA[currentModeKey] || ROUTE_METADATA.stego
    document.title = meta.title

    let descMeta = document.querySelector('meta[name="description"]')
    if (descMeta) {
      descMeta.setAttribute('content', meta.description)
    }

    let canonicalLink = document.querySelector('link[rel="canonical"]')
    if (canonicalLink) {
      canonicalLink.setAttribute('href', `https://invisio-vault.vercel.app${meta.path === '/steganography' && clean === '' ? '/' : meta.path}`)
    }
  }, [location.pathname])

  const handleModeSelect = (newMode) => {
    setMode(newMode)
    if (newMode === 'stego') {
      setActiveTab('hide')
      navigate('/steganography')
    } else if (newMode === 'polyglot') {
      navigate('/polyglot')
    } else if (newMode === 'qrcode') {
      navigate('/qr-code')
    }
  }

  const handleModeKeyDown = (e) => {
    const modes = ['stego', 'polyglot', 'qrcode']
    const currentIndex = modes.indexOf(mode)
    let newIndex = currentIndex

    if (e.key === 'ArrowRight') {
      newIndex = (currentIndex + 1) % modes.length
    } else if (e.key === 'ArrowLeft') {
      newIndex = (currentIndex - 1 + modes.length) % modes.length
    } else if (e.key === 'Home') {
      newIndex = 0
    } else if (e.key === 'End') {
      newIndex = modes.length - 1
    } else {
      return
    }

    e.preventDefault()
    const nextMode = modes[newIndex]
    handleModeSelect(nextMode)
    document.getElementById(`tab-${nextMode}`)?.focus()
  }

  const handleSubTabKeyDown = (e) => {
    const tabs = ['hide', 'extract']
    const currentIndex = tabs.indexOf(activeTab)
    let newIndex = currentIndex

    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      newIndex = currentIndex === 0 ? 1 : 0
      e.preventDefault()
      const nextTab = tabs[newIndex]
      setActiveTab(nextTab)
      document.getElementById(`tab-${nextTab}`)?.focus()
    }
  }

  return (
    <div className="app">
      {/* Skip to main content link for keyboard users (WCAG 2.4.1) */}
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>

      <header className="app-header">
        <div className="header-top">
          <WakeServerButton />
          <button
            className="info-button"
            onClick={() => {
              setShowTutorial(true)
              navigate('/docs')
            }}
            title="InvisioVault Cryptographic Documentation & Guides"
            aria-label="InvisioVault Cryptographic Documentation & Guides"
          >
            <HelpCircle size={20} />
          </button>
        </div>
        <h1 className="brand-title">
          <Shield className="brand-icon" size={28} />
          <span>InvisioVault</span>
        </h1>
        <p>Advanced steganography, universal polyglots &amp; stealth QR barcodes</p>
      </header>

      {/* Main Mode Navigation (WCAG Tablist pattern with Deep Routing) */}
      <div
        className="mode-container"
        role="tablist"
        aria-label="Application primary modes"
        onKeyDown={handleModeKeyDown}
      >
        <button
          id="tab-stego"
          role="tab"
          aria-selected={mode === 'stego'}
          aria-controls="panel-stego"
          tabIndex={mode === 'stego' ? 0 : -1}
          className={`mode-tab ${mode === 'stego' ? 'active' : ''}`}
          onClick={() => handleModeSelect('stego')}
        >
          <ImageIcon size={18} aria-hidden="true" />
          <span>Steganography</span>
        </button>
        <button
          id="tab-polyglot"
          role="tab"
          aria-selected={mode === 'polyglot'}
          aria-controls="panel-polyglot"
          tabIndex={mode === 'polyglot' ? 0 : -1}
          className={`mode-tab ${mode === 'polyglot' ? 'active' : ''}`}
          onClick={() => handleModeSelect('polyglot')}
        >
          <Layers size={18} aria-hidden="true" />
          <span>Polyglot</span>
        </button>
        <button
          id="tab-qrcode"
          role="tab"
          aria-selected={mode === 'qrcode'}
          aria-controls="panel-qrcode"
          tabIndex={mode === 'qrcode' ? 0 : -1}
          className={`mode-tab ${mode === 'qrcode' ? 'active' : ''}`}
          onClick={() => handleModeSelect('qrcode')}
        >
          <QrCode size={18} aria-hidden="true" />
          <span>QR Code</span>
        </button>
      </div>

      <main id="main-content" tabIndex={-1} className="main-landmark">
        <Suspense fallback={<ComponentLoader />}>
          {mode === 'stego' ? (
            <div
              id="panel-stego"
              role="tabpanel"
              aria-labelledby="tab-stego"
            >
              <div
                className="tab-container"
                role="tablist"
                aria-label="Steganography action tabs"
                onKeyDown={handleSubTabKeyDown}
              >
                <button
                  id="tab-hide"
                  role="tab"
                  aria-selected={activeTab === 'hide'}
                  aria-controls="panel-stego-content"
                  tabIndex={activeTab === 'hide' ? 0 : -1}
                  className={`tab ${activeTab === 'hide' ? 'active' : ''}`}
                  onClick={() => setActiveTab('hide')}
                >
                  Hide File
                </button>
                <button
                  id="tab-extract"
                  role="tab"
                  aria-selected={activeTab === 'extract'}
                  aria-controls="panel-stego-content"
                  tabIndex={activeTab === 'extract' ? 0 : -1}
                  className={`tab ${activeTab === 'extract' ? 'active' : ''}`}
                  onClick={() => setActiveTab('extract')}
                >
                  Extract File
                </button>
              </div>

              <div
                id="panel-stego-content"
                role="tabpanel"
                aria-labelledby={`tab-${activeTab}`}
                className="content"
              >
                {activeTab === 'hide' ? <HideFile /> : <ExtractFile />}
              </div>
            </div>
          ) : mode === 'polyglot' ? (
            <div
              id="panel-polyglot"
              role="tabpanel"
              aria-labelledby="tab-polyglot"
              className="content"
            >
              <Polyglot />
            </div>
          ) : (
            <div
              id="panel-qrcode"
              role="tabpanel"
              aria-labelledby="tab-qrcode"
              className="content"
            >
              <QRCode />
            </div>
          )}
        </Suspense>
      </main>

      {/* Crawlable and Accessible On-Page Educational & FAQ Content */}
      <SeoContent />

      <footer className="app-footer">
        <p>&copy; {new Date().getFullYear()} InvisioVault | Crafted by <a href="https://rolan-rnr.netlify.app/" target="_blank" rel="noopener noreferrer">Rolan</a></p>
      </footer>

      <Suspense fallback={null}>
        {showTutorial && (
          <TutorialModal
            isOpen={showTutorial}
            onClose={() => {
              setShowTutorial(false)
              if (location.pathname.replace(/\/$/, '') === '/docs') {
                navigate('/steganography')
              }
            }}
          />
        )}
      </Suspense>
    </div>
  )
}

export default App
