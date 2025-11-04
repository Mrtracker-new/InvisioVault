import { useState } from 'react'
import HideFile from './components/HideFile'
import ExtractFile from './components/ExtractFile'
import './App.css'

function App() {
  const [activeTab, setActiveTab] = useState('hide')

  return (
    <div className="app">
      <header className="app-header">
        <h1>🔒 InvisioVault</h1>
        <p>Secure file hiding in images using steganography</p>
      </header>

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

      <footer className="app-footer">
        <p>&copy; 2025 InvisioVault | Built with ❤️ by Rolan</p>
      </footer>
    </div>
  )
}

export default App
