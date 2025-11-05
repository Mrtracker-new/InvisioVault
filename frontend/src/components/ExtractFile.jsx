import { useState } from 'react'
import axios from 'axios'
import './ExtractFile.css'
import API_URL from '../config/api'

function ExtractFile() {
  const [image, setImage] = useState(null)
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [extractedText, setExtractedText] = useState('')
  const [extractedFilename, setExtractedFilename] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')

    if (!image) {
      setError('Please select an image with a hidden file')
      return
    }

    setLoading(true)

    try {
      const formData = new FormData()
      formData.append('image', image)
      if (password) {
        formData.append('password', password)
      }

      const response = await axios.post(`${API_URL}/api/extract`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        },
        responseType: 'blob'
      })

      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      
      // Get filename from Content-Disposition header
      const contentDisposition = response.headers['content-disposition']
      let filename = 'extracted_file.bin' // Default fallback with extension
      if (contentDisposition) {
        // Try to match filename with various formats
        const filenameRegex = /filename\*?=["']?(?:UTF-\d["'])?([^;\r\n"']*)["']?/i
        const filenameMatch = contentDisposition.match(filenameRegex)
        if (filenameMatch && filenameMatch[1]) {
          filename = decodeURIComponent(filenameMatch[1].trim())
        }
      }
      
      // Check if it's a text file
      if (filename.endsWith('.txt')) {
        // Display text content instead of downloading
        const text = await response.data.text()
        setExtractedText(text)
        setExtractedFilename(filename)
      } else {
        // Download non-text files
        link.setAttribute('download', filename)
        document.body.appendChild(link)
        link.click()
        link.remove()
        window.URL.revokeObjectURL(url)
        alert('File extracted successfully!')
      }

      setImage(null)
      setPassword('')
      document.getElementById('extract-image-input').value = ''
    } catch (err) {
      setError(err.response?.data?.error || 'An error occurred while extracting the file')
    } finally {
      setLoading(false)
    }
  }

  const handleDownloadText = () => {
    const blob = new Blob([extractedText], { type: 'text/plain' })
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.setAttribute('download', extractedFilename)
    document.body.appendChild(link)
    link.click()
    link.remove()
    window.URL.revokeObjectURL(url)
  }

  return (
    <div className="extract-file">
      <h2>Extract Hidden File from Image</h2>
      <p className="description">
        Upload an image that contains a hidden file. The file will be extracted and downloaded automatically.
      </p>

      {extractedText ? (
        <div className="text-display">
          <h3>✅ Text Extracted Successfully!</h3>
          <p className="filename">File: {extractedFilename}</p>
          <div className="text-content">
            <pre>{extractedText}</pre>
          </div>
          <div className="text-actions">
            <button onClick={handleDownloadText} className="download-button">
              📥 Download as Text File
            </button>
            <button
              onClick={() => {
                setExtractedText('')
                setExtractedFilename('')
              }}
              className="new-button"
            >
              Extract Another
            </button>
          </div>
        </div>
      ) : (

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="extract-image-input">Select Image (PNG, JPG, JPEG, BMP)</label>
          <input
            id="extract-image-input"
            type="file"
            accept="image/png,image/jpeg,image/bmp"
            onChange={(e) => setImage(e.target.files[0])}
            required
          />
          {image && <p className="file-name">Selected: {image.name}</p>}
        </div>

        <div className="form-group">
          <label htmlFor="extract-password-input">Password (Optional) 🔒</label>
          <div className="password-input-wrapper">
            <input
              id="extract-password-input"
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
            <li>Upload an image that was created using InvisioVault</li>
            <li>The hidden file will be extracted with its original name</li>
            <li>The file will download automatically to your device</li>
            <li>Text files will be displayed on screen</li>
          </ul>
        </div>
      </form>
      )}
    </div>
  )
}

export default ExtractFile
