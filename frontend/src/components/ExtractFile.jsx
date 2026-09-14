import { useState } from 'react'
import { CheckCircle2, Download, Lock, Info, Copy, Check, Eye, EyeOff } from 'lucide-react'
import axios from 'axios'
import './ExtractFile.css'
import API_URL from '../config/api'
import { getApiErrorMessage } from '../utils/apiError'
import FileDropzone from './FileDropzone'
import StepProgress from './StepProgress'
import ProcessingIndicator from './ProcessingIndicator'

const STEPS = [
  { id: 1, label: 'Select Stego Image' },
  { id: 2, label: 'Security (Password)' },
  { id: 3, label: 'Extract & Reveal' }
]

function ExtractFile() {
  const [image, setImage] = useState(null)
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [successMessage, setSuccessMessage] = useState('')
  const [extractedText, setExtractedText] = useState('')
  const [extractedFilename, setExtractedFilename] = useState('')
  const [copied, setCopied] = useState(false)

  const getCurrentStep = () => {
    if (extractedText || successMessage || loading) return 3
    if (image) return 2
    return 1
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccessMessage('')

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
        const url = window.URL.createObjectURL(new Blob([response.data]))
        const link = document.createElement('a')
        link.href = url
        link.setAttribute('download', filename)
        document.body.appendChild(link)
        link.click()
        link.remove()
        window.URL.revokeObjectURL(url)
        setSuccessMessage(`"${filename}" extracted and downloaded successfully!`)
        setTimeout(() => setSuccessMessage(''), 4000)
      }

      setImage(null)
      setPassword('')
    } catch (err) {
      // responseType is 'blob', so the error body is a Blob that must be
      // parsed to recover the server's message (e.g. "Incorrect password.")
      setError(await getApiErrorMessage(err, 'An error occurred while extracting the file'))
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

  const handleCopyText = async () => {
    if (!extractedText) return
    try {
      await navigator.clipboard.writeText(extractedText)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Fallback
      const textArea = document.createElement('textarea')
      textArea.value = extractedText
      document.body.appendChild(textArea)
      textArea.select()
      document.execCommand('copy')
      document.body.removeChild(textArea)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const charCount = extractedText ? extractedText.length : 0
  const wordCount = extractedText ? extractedText.trim().split(/\s+/).filter(Boolean).length : 0

  const processingStages = [
    'Reading carrier image headers...',
    'Scanning LSB pixel bitstream...',
    password ? 'Decrypting payload with password...' : 'Unpacking bitstream...',
    'Extracting payload content...'
  ]

  return (
    <div className="extract-file">
      <h2>Extract Hidden File from Image</h2>
      <p className="description">
        Upload an image that contains a hidden file. The file will be extracted and downloaded automatically.
      </p>

      {/* Visual Step Progression */}
      <StepProgress steps={STEPS} currentStep={getCurrentStep()} />

      {extractedText ? (
        <div className="text-display">
          <div className="text-display-header">
            <h3 style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}>
              <CheckCircle2 size={20} aria-hidden="true" />
              <span>Text Extracted Successfully!</span>
            </h3>
            <div className="text-badges">
              <span className="text-badge">{charCount} chars</span>
              <span className="text-badge">{wordCount} words</span>
            </div>
          </div>
          <p className="filename">File: {extractedFilename}</p>

          <div className="text-content-wrapper">
            <div className="text-content">
              <pre>{extractedText}</pre>
            </div>
            <button
              type="button"
              className="copy-text-btn"
              onClick={handleCopyText}
              title="Copy extracted text"
              aria-label="Copy extracted text to clipboard"
            >
              {copied ? (
                <>
                  <Check size={16} aria-hidden="true" />
                  <span>Copied!</span>
                </>
              ) : (
                <>
                  <Copy size={16} aria-hidden="true" />
                  <span>Copy</span>
                </>
              )}
            </button>
          </div>

          <div className="text-actions">
            <button type="button" onClick={handleDownloadText} className="download-button">
              <Download size={16} aria-hidden="true" />
              <span>Download as Text File</span>
            </button>
            <button
              type="button"
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
        <form onSubmit={handleSubmit} aria-describedby={error ? 'extract-error-msg' : undefined}>
          <FileDropzone
            id="extract-image-input"
            label="Select Stego Image (PNG, JPG, JPEG, BMP)"
            accept="image/png,image/jpeg,image/bmp"
            file={image}
            onFileSelect={(f) => { setImage(f); setError(''); }}
            onClear={() => setImage(null)}
            helperText="Drag & drop or browse the carrier image containing the secret"
            required
            disabled={loading}
          />

          <div className="form-group">
            <label htmlFor="extract-password-input" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
              <span>Password (Optional)</span>
              <Lock size={14} style={{ opacity: 0.7 }} aria-hidden="true" />
            </label>
            <div className="password-input-wrapper">
              <input
                id="extract-password-input"
                type={showPassword ? "text" : "password"}
                placeholder="Enter password if the file was encrypted"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={loading}
              />
              {password && (
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  aria-pressed={showPassword}
                  disabled={loading}
                >
                  {showPassword ? (
                    <EyeOff size={18} aria-hidden="true" />
                  ) : (
                    <Eye size={18} aria-hidden="true" />
                  )}
                </button>
              )}
            </div>
          </div>

          {successMessage && (
            <div className="success-message" role="status" aria-live="polite" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <CheckCircle2 size={16} style={{ flexShrink: 0 }} aria-hidden="true" />
              <span>{successMessage}</span>
            </div>
          )}
          {error && <div id="extract-error-msg" className="error-message" role="alert">{error}</div>}

          {/* Staged Micro-Processing Indicator */}
          <ProcessingIndicator
            isActive={loading}
            stages={processingStages}
          />

          <button
            type="submit"
            disabled={loading}
            className="submit-button"
            aria-busy={loading}
          >
            {loading ? 'Extracting File...' : 'Extract File'}
          </button>

          <div className="info-box">
            <h4>
              <Info size={16} aria-hidden="true" />
              <span>How it works</span>
            </h4>
            <ul>
              <li>Upload an image that was created using InvisioVault</li>
              <li>The hidden file will be extracted with its original name</li>
              <li>The file will download automatically to your device</li>
              <li>Text files will be displayed on screen with quick copy</li>
            </ul>
          </div>
        </form>
      )}
    </div>
  )
}

export default ExtractFile
