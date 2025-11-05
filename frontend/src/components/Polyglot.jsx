import { useState } from 'react'
import axios from 'axios'
import './Polyglot.css'
import API_URL from '../config/api'

function Polyglot() {
  const [mode, setMode] = useState('create') // 'create' or 'extract'
  const [carrierFile, setCarrierFile] = useState(null)
  const [fileToHide, setFileToHide] = useState(null)
  const [polyglotFile, setPolyglotFile] = useState(null)
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const [downloadId, setDownloadId] = useState('')

  const handleCreate = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess(false)

    if (!carrierFile || !fileToHide) {
      setError('Please select both carrier file and file to hide')
      return
    }

    setLoading(true)

    try {
      const formData = new FormData()
      formData.append('carrier', carrierFile)
      formData.append('file', fileToHide)
      if (password) {
        formData.append('password', password)
      }

      const response = await axios.post(`${API_URL}/api/polyglot/create`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })

      setDownloadId(response.data.download_id)
      setSuccess(true)
      setCarrierFile(null)
      setFileToHide(null)
      setPassword('')
      document.getElementById('carrier-input').value = ''
      document.getElementById('hide-input').value = ''
    } catch (err) {
      setError(err.response?.data?.error || 'An error occurred while creating the polyglot file')
    } finally {
      setLoading(false)
    }
  }

  const handleExtract = async (e) => {
    e.preventDefault()
    setError('')

    if (!polyglotFile) {
      setError('Please select a polyglot file')
      return
    }

    setLoading(true)

    try {
      const formData = new FormData()
      formData.append('file', polyglotFile)
      if (password) {
        formData.append('password', password)
      }

      const response = await axios.post(`${API_URL}/api/polyglot/extract`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        },
        responseType: 'blob'
      })

      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      
      const contentDisposition = response.headers['content-disposition']
      let filename = 'extracted_file'
      if (contentDisposition) {
        const filenameRegex = /filename\*?=["']?(?:UTF-\d["'])?([^;\r\n"']*)["]?/i
        const filenameMatch = contentDisposition.match(filenameRegex)
        if (filenameMatch && filenameMatch[1]) {
          filename = decodeURIComponent(filenameMatch[1].trim())
        }
      }
      
      link.setAttribute('download', filename)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)

      setPolyglotFile(null)
      setPassword('')
      document.getElementById('polyglot-input').value = ''
      alert('File extracted successfully!')
    } catch (err) {
      setError(err.response?.data?.error || 'An error occurred while extracting the file')
    } finally {
      setLoading(false)
    }
  }

  const handleDownload = () => {
    window.open(`${API_URL}/api/polyglot/download/${downloadId}`, '_blank')
  }

  return (
    <div className="polyglot">
      <h2>🔗 Polyglot File Hiding</h2>
      <p className="description">
        Create polyglot files by appending hidden data to any carrier file. The carrier file remains functional while hiding your secret data.
      </p>

      <div className="mode-selector">
        <button
          type="button"
          className={`mode-btn ${mode === 'create' ? 'active' : ''}`}
          onClick={() => { setMode('create'); setError(''); setSuccess(false); }}
        >
          📦 Create Polyglot
        </button>
        <button
          type="button"
          className={`mode-btn ${mode === 'extract' ? 'active' : ''}`}
          onClick={() => { setMode('extract'); setError(''); setSuccess(false); }}
        >
          📂 Extract from Polyglot
        </button>
      </div>

      {mode === 'create' ? (
        !success ? (
          <form onSubmit={handleCreate}>
            <div className="form-group">
              <label htmlFor="carrier-input">Select Carrier File (Any Format)</label>
              <input
                id="carrier-input"
                type="file"
                onChange={(e) => setCarrierFile(e.target.files[0])}
                required
              />
              {carrierFile && <p className="file-name">Selected: {carrierFile.name}</p>}
            </div>

            <div className="form-group">
              <label htmlFor="hide-input">Select File to Hide</label>
              <input
                id="hide-input"
                type="file"
                onChange={(e) => setFileToHide(e.target.files[0])}
                required
              />
              {fileToHide && <p className="file-name">Selected: {fileToHide.name}</p>}
            </div>

            <div className="form-group">
              <label htmlFor="polyglot-password-input">Password (Optional) 🔒</label>
              <div className="password-input-wrapper">
                <input
                  id="polyglot-password-input"
                  type={showPassword ? "text" : "password"}
                  placeholder="Enter password to protect the ZIP"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                {password && (
                  <button
                    type="button"
                    className="password-toggle"
                    onClick={() => setShowPassword(!showPassword)}
                    aria-label="Toggle password visibility"
                  >
                    {showPassword ? (
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                        <circle cx="12" cy="12" r="3"></circle>
                      </svg>
                    ) : (
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                        <line x1="1" y1="1" x2="23" y2="23"></line>
                      </svg>
                    )}
                  </button>
                )}
              </div>
              {password && <p className="file-name">🔐 ZIP will be password-protected</p>}
            </div>

            {error && <div className="error-message">{error}</div>}

            <button type="submit" disabled={loading} className="submit-button">
              {loading ? 'Creating...' : 'Create Polyglot'}
            </button>

            <div className="info-box">
              <h4>ℹ️ How it works</h4>
              <ul>
                <li>Your file will be zipped and appended to the carrier file</li>
                <li>The carrier file remains fully functional</li>
                <li>Works with images, PDFs, videos, executables, etc.</li>
              </ul>
            </div>
          </form>
        ) : (
          <div className="success-card">
            <div className="success-icon">✅</div>
            <h3>Polyglot Created Successfully!</h3>
            <p>Your file has been hidden inside the carrier file.</p>
            <button onClick={handleDownload} className="download-button">
              📥 Download Polyglot File
            </button>
            <button
              onClick={() => {
                setSuccess(false)
                setDownloadId('')
              }}
              className="new-button"
            >
              Create Another
            </button>
          </div>
        )
      ) : (
        <form onSubmit={handleExtract}>
          <div className="form-group">
            <label htmlFor="polyglot-input">Select Polyglot File</label>
            <input
              id="polyglot-input"
              type="file"
              onChange={(e) => setPolyglotFile(e.target.files[0])}
              required
            />
            {polyglotFile && <p className="file-name">Selected: {polyglotFile.name}</p>}
          </div>

          <div className="form-group">
            <label htmlFor="extract-polyglot-password">Password (Optional) 🔒</label>
            <div className="password-input-wrapper">
              <input
                id="extract-polyglot-password"
                type={showPassword ? "text" : "password"}
                placeholder="Enter password if the file was encrypted"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              {password && (
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label="Toggle password visibility"
                >
                  {showPassword ? (
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                      <circle cx="12" cy="12" r="3"></circle>
                    </svg>
                  ) : (
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                      <line x1="1" y1="1" x2="23" y2="23"></line>
                    </svg>
                  )}
                </button>
              )}
            </div>
          </div>

          {error && <div className="error-message">{error}</div>}

          <button type="submit" disabled={loading} className="submit-button">
            {loading ? 'Extracting...' : 'Extract File'}
          </button>

          <div className="info-box">
            <h4>ℹ️ How it works</h4>
            <ul>
              <li>Upload a file created with InvisioVault Polyglot</li>
              <li>The hidden file will be extracted and downloaded</li>
              <li>The carrier file is not modified</li>
            </ul>
          </div>
        </form>
      )}
    </div>
  )
}

export default Polyglot
