import { useState } from 'react'
import HideFile from './components/HideFile'
import ExtractFile from './components/ExtractFile'
import Polyglot from './components/Polyglot'
import TutorialModal from './components/TutorialModal'
import './App.css'

function App() {
  const [mode, setMode] = useState('stego') // 'stego' or 'polyglot'
  const [activeTab, setActiveTab] = useState('hide')
  const [showTutorial, setShowTutorial] = useState(false)

  return (
    <div className="app">
      <header className="app-header">
        <button 
          className="info-button" 
          onClick={() => setShowTutorial(true)}
          title="How to use InvisioVault"
        >
          ℹ️
        </button>
        <h1>🔒 InvisioVault</h1>
        <p>Secure file hiding using steganography and polyglot techniques</p>
      </header>

      <div className="mode-container">
        <button
          className={`mode-tab ${mode === 'stego' ? 'active' : ''}`}
          onClick={() => { setMode('stego'); setActiveTab('hide'); }}
        >
          🖼️ Steganography
        </button>
        <button
          className={`mode-tab ${mode === 'polyglot' ? 'active' : ''}`}
          onClick={() => setMode('polyglot')}
        >
          🔗 Polyglot
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
      ) : (
        <div className="content">
          <Polyglot />
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
