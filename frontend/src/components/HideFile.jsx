import { useState } from 'react'
import axios from 'axios'
import './HideFile.css'
import API_URL from '../config/api'

function HideFile() {
  const [mode, setMode] = useState('file') // 'file' or 'text'
  const [image, setImage] = useState(null)
  const [file, setFile] = useState(null)
  const [text, setText] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const [downloadId, setDownloadId] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess(false)

    if (!image) {
      setError('Please select an image')
      return
    }
    
    if (mode === 'file' && !file) {
      setError('Please select a file to hide')
      return
    }
    
    if (mode === 'text' && !text.trim()) {
      setError('Please enter some text to hide')
      return
    }

    setLoading(true)

    try {
      const formData = new FormData()
      formData.append('image', image)
      
      if (mode === 'file') {
        formData.append('file', file)
      } else {
        formData.append('text', text)
      }
      
      if (password) {
        formData.append('password', password)
      }

      const response = await axios.post(`${API_URL}/api/hide`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })

      setDownloadId(response.data.download_id)
      setSuccess(true)
      setImage(null)
      setFile(null)
      setText('')
      setPassword('')
      // Reset file inputs
      document.getElementById('image-input').value = ''
      if (mode === 'file') {
        document.getElementById('file-input').value = ''
      }
    } catch (err) {
      setError(err.response?.data?.error || 'An error occurred while hiding the file')
    } finally {
      setLoading(false)
    }
  }

  const handleDownload = () => {
    window.open(`${API_URL}/api/download/${downloadId}`, '_blank')
  }

  return (
    <div className="hide-file">
      <h2>Hide a File in an Image</h2>
      <p className="description">
        Upload an image and a file. The file will be securely hidden within the image using steganography.
      </p>

      {!success ? (
        <form onSubmit={handleSubmit}>
          <div className="mode-selector">
            <button
              type="button"
              className={`mode-btn ${mode === 'file' ? 'active' : ''}`}
              onClick={() => setMode('file')}
            >
              📄 Hide File
            </button>
            <button
              type="button"
              className={`mode-btn ${mode === 'text' ? 'active' : ''}`}
              onClick={() => setMode('text')}
            >
              📝 Hide Text
            </button>
          </div>

          <div className="form-group">
            <label htmlFor="image-input">Select Image (PNG, JPG, JPEG, BMP)</label>
            <input
              id="image-input"
              type="file"
              accept="image/png,image/jpeg,image/bmp"
              onChange={(e) => setImage(e.target.files[0])}
              required
            />
            {image && <p className="file-name">Selected: {image.name}</p>}
          </div>

          {mode === 'file' ? (
            <div className="form-group">
              <label htmlFor="file-input">Select File to Hide</label>
              <input
                id="file-input"
                type="file"
                onChange={(e) => setFile(e.target.files[0])}
              />
              {file && <p className="file-name">Selected: {file.name}</p>}
            </div>
          ) : (
            <div className="form-group">
              <label htmlFor="text-input">Enter Text to Hide</label>
              <textarea
                id="text-input"
                placeholder="Type your secret message here..."
                value={text}
                onChange={(e) => setText(e.target.value)}
                rows="6"
              />
              {text && <p className="file-name">Characters: {text.length}</p>}
            </div>
          )}

          <div className="form-group">
            <label htmlFor="password-input">Password (Optional) 🔒</label>
            <div className="password-input-wrapper">
              <input
                id="password-input"
                type={showPassword ? "text" : "password"}
                placeholder="Enter password to encrypt the file"
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
            {password && <p className="file-name">🔐 File will be password-protected</p>}
          </div>

          {error && <div className="error-message">{error}</div>}

          <button type="submit" disabled={loading} className="submit-button">
            {loading ? 'Processing...' : 'Hide File'}
          </button>
        </form>
      ) : (
        <div className="success-card">
          <div className="success-icon">✅</div>
          <h3>File Hidden Successfully!</h3>
          <p>Your file has been securely hidden in the image.</p>
          <button onClick={handleDownload} className="download-button">
            📥 Download Image
          </button>
          <button
            onClick={() => {
              setSuccess(false)
              setDownloadId('')
            }}
            className="new-button"
          >
            Hide Another File
          </button>
        </div>
      )}
    </div>
  )
}

export default HideFile
