import { useState } from 'react'
import HideFile from './components/HideFile'
import ExtractFile from './components/ExtractFile'
import Polyglot from './components/Polyglot'
import './App.css'

function App() {
  const [mode, setMode] = useState('stego') // 'stego' or 'polyglot'
  const [activeTab, setActiveTab] = useState('hide')

  return (
    <div className="app">
      <header className="app-header">
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
        <p>&copy; 2025 InvisioVault | Built with ❤️ by Rolan</p>
      </footer>
    </div>
  )
}

export default App
