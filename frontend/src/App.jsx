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

  return (
    <div className="app">
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

      <div className="mode-container">
        <button
          className={`mode-tab ${mode === 'stego' ? 'active' : ''}`}
          onClick={() => { setMode('stego'); setActiveTab('hide'); }}
        >
          <ImageIcon size={18} />
          <span>Steganography</span>
        </button>
        <button
          className={`mode-tab ${mode === 'polyglot' ? 'active' : ''}`}
          onClick={() => setMode('polyglot')}
        >
          <Layers size={18} />
          <span>Polyglot</span>
        </button>
        <button
          className={`mode-tab ${mode === 'qrcode' ? 'active' : ''}`}
          onClick={() => setMode('qrcode')}
        >
          <QrCode size={18} />
          <span>QR Code</span>
        </button>
      </div>

      {mode === 'stego' ? (
        <>
          <div className="tab-container">
            <button
              className={`tab ${activeTab === 'hide' ? 'active' : ''}`}
              onClick={() => setActiveTab('hide')}
            >
              Hide File
            </button>
            <button
              className={`tab ${activeTab === 'extract' ? 'active' : ''}`}
              onClick={() => setActiveTab('extract')}
            >
              Extract File
            </button>
          </div>

          <div className="content">
            {activeTab === 'hide' ? <HideFile /> : <ExtractFile />}
          </div>
        </>
      ) : mode === 'polyglot' ? (
        <div className="content">
          <Polyglot />
        </div>
      ) : (
        <div className="content">
          <QRCode />
        </div>
      )}

      <footer className="app-footer">
        <p>&copy; 2025 InvisioVault | Crafted by <a href="https://rolan-rnr.netlify.app/" target="_blank" rel="noopener noreferrer">Rolan</a></p>
      </footer>

      <TutorialModal
        isOpen={showTutorial}
        onClose={() => setShowTutorial(false)}
      />
    </div>
  )
}

export default App
