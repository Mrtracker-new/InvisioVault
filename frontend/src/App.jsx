import { useState } from 'react'
import { HelpCircle, Shield, Image as ImageIcon, Layers, QrCode } from 'lucide-react'
import HideFile from './components/HideFile'
import ExtractFile from './components/ExtractFile'
import Polyglot from './components/Polyglot'
import QRCode from './components/QRCode'
import TutorialModal from './components/TutorialModal'
import WakeServerButton from './components/WakeServerButton'
import './App.css'


function App() {
  const [mode, setMode] = useState('stego') // 'stego', 'polyglot', or 'qrcode'
  const [activeTab, setActiveTab] = useState('hide')
  const [showTutorial, setShowTutorial] = useState(false)

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
    setMode(nextMode)
    if (nextMode === 'stego') setActiveTab('hide')
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
            onClick={() => setShowTutorial(true)}
            title="How to use InvisioVault"
            aria-label="How to use InvisioVault"
          >
            <HelpCircle size={20} />
          </button>
        </div>
        <h1 className="brand-title">
          <Shield className="brand-icon" size={28} />
          <span>InvisioVault</span>
        </h1>
        <p>Secure file hiding using steganography and polyglot techniques</p>
      </header>

      {/* Main Mode Navigation (WCAG Tablist pattern) */}
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
          onClick={() => { setMode('stego'); setActiveTab('hide'); }}
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
          onClick={() => setMode('polyglot')}
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
          onClick={() => setMode('qrcode')}
        >
          <QrCode size={18} aria-hidden="true" />
          <span>QR Code</span>
        </button>
      </div>

      <main id="main-content" tabIndex={-1} className="main-landmark">
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
      </main>

      <footer className="app-footer">
        <p>&copy; {new Date().getFullYear()} InvisioVault | Crafted by <a href="https://rolan-rnr.netlify.app/" target="_blank" rel="noopener noreferrer">Rolan</a></p>
      </footer>

      <TutorialModal
        isOpen={showTutorial}
        onClose={() => setShowTutorial(false)}
      />
    </div>
  )
}

export default App
