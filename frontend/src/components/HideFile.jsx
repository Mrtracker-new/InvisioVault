import { useState } from 'react'
import { FileText, Type, Lock, AlertTriangle, ShieldCheck, ShieldAlert, ShieldX, CheckCircle2, Download } from 'lucide-react'
import axios from 'axios'
import './HideFile.css'
import API_URL from '../config/api'
import CapacityIndicator from './CapacityIndicator'
import FileDropzone from './FileDropzone'
import StepProgress from './StepProgress'
import ProcessingIndicator from './ProcessingIndicator'

const STEPS = [
  { id: 1, label: 'Carrier Image' },
  { id: 2, label: 'Secret Payload' },
  { id: 3, label: 'Security & Config' },
  { id: 4, label: 'Generate & Download' }
]

function HideFile() {
  const [mode, setMode] = useState('file') // 'file' or 'text'
  const [image, setImage] = useState(null)
  const [file, setFile] = useState(null)
  const [text, setText] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [passwordError, setPasswordError] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const [downloadId, setDownloadId] = useState('')

  const MIN_PASSWORD_LENGTH = 8

  const getCurrentStep = () => {
    if (success || loading) return 4
    const hasPayload = mode === 'file' ? !!file : !!text.trim()
    if (image && hasPayload) return 3
    if (image) return 2
    return 1
  }

  const getPasswordStrength = (pwd) => {
    if (!pwd) return null
    if (pwd.length < MIN_PASSWORD_LENGTH) return 'weak'
    const hasUpper = /[A-Z]/.test(pwd)
    const hasLower = /[a-z]/.test(pwd)
    const hasDigit = /\d/.test(pwd)
    const hasSpecial = /[^A-Za-z0-9]/.test(pwd)
    const score = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length
    if (pwd.length >= 12 && score >= 3) return 'strong'
    if (pwd.length >= 8 && score >= 2) return 'medium'
    return 'weak'
  }

  const handlePasswordChange = (e) => {
    const val = e.target.value
    setPassword(val)
    if (val && val.length < MIN_PASSWORD_LENGTH) {
      setPasswordError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`)
    } else {
      setPasswordError('')
    }
  }

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

    if (password && password.length < MIN_PASSWORD_LENGTH) {
      setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters long`)
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
    } catch (err) {
      setError(err.response?.data?.error || 'An error occurred while hiding the file')
    } finally {
      setLoading(false)
    }
  }

  const handleDownload = () => {
    const link = document.createElement('a')
    link.href = `${API_URL}/api/download/${downloadId}`
    link.setAttribute('download', 'invisiovault_image.png')
    document.body.appendChild(link)
    link.click()
    link.remove()
  }

  const processingStages = [
    'Analyzing carrier image structure...',
    mode === 'file' ? 'Compressing payload...' : 'Encoding text payload...',
    password ? 'Encrypting payload with Fernet (AES)...' : 'Preparing bitstream...',
    'Embedding secret bits into LSB pixels...',
    'Finalizing steganographic image...'
  ]

  return (
    <div className="hide-file">
      <h2>Hide a File in an Image</h2>
      <p className="description">
        Upload an image and a file. The file will be securely hidden within the image using steganography.
      </p>

      {/* Visual Step Progression */}
      <StepProgress steps={STEPS} currentStep={getCurrentStep()} />

      {!success ? (
        <form onSubmit={handleSubmit}>
          <div className="mode-selector" role="tablist" aria-label="Payload type">
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'file'}
              className={`mode-btn ${mode === 'file' ? 'active' : ''}`}
              onClick={() => setMode('file')}
            >
              <FileText size={16} aria-hidden="true" />
              <span>Hide File</span>
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'text'}
              className={`mode-btn ${mode === 'text' ? 'active' : ''}`}
              onClick={() => setMode('text')}
            >
              <Type size={16} aria-hidden="true" />
              <span>Hide Text</span>
            </button>
          </div>

          {/* Carrier Image Dropzone */}
          <FileDropzone
            id="carrier-image-input"
            label="Carrier Image (PNG, JPG, JPEG, BMP)"
            accept="image/png,image/jpeg,image/bmp"
            file={image}
            onFileSelect={(f) => { setImage(f); setError(''); }}
            onClear={() => setImage(null)}
            helperText="Drag & drop or browse from device (PNG, JPG, or BMP)"
            required
            disabled={loading}
          />

          {mode === 'file' ? (
            /* Secret File Dropzone */
            <FileDropzone
              id="secret-file-input"
              label="Secret File to Hide"
              file={file}
              onFileSelect={(f) => { setFile(f); setError(''); }}
              onClear={() => setFile(null)}
              helperText="Any file type (documents, archives, keys, media)"
              disabled={loading}
            />
          ) : (
            <div className="form-group">
              <label htmlFor="text-input">Enter Text to Hide</label>
              <textarea
                id="text-input"
                placeholder="Type your secret message here..."
                value={text}
                onChange={(e) => setText(e.target.value)}
                rows="5"
                disabled={loading}
              />
              {text && <p className="char-count">Characters: {text.length}</p>}
            </div>
          )}

          <div className="form-group">
            <label htmlFor="password-input" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
              <span>Password (Optional)</span>
              <Lock size={14} style={{ opacity: 0.7 }} aria-hidden="true" />
            </label>
            <div className="password-input-wrapper">
              <input
                id="password-input"
                type={showPassword ? "text" : "password"}
                placeholder="Enter password to encrypt the file (min. 8 chars)"
                value={password}
                onChange={handlePasswordChange}
                aria-describedby={passwordError ? 'hide-password-error' : undefined}
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
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                      <circle cx="12" cy="12" r="3"></circle>
                    </svg>
                  ) : (
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                      <line x1="1" y1="1" x2="23" y2="23"></line>
                    </svg>
                  )}
                </button>
              )}
            </div>
            {passwordError && (
              <p id="hide-password-error" className="password-error-msg" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }} role="alert">
                <AlertTriangle size={14} style={{ flexShrink: 0 }} aria-hidden="true" />
                <span>{passwordError}</span>
              </p>
            )}
            {password && !passwordError && (
              <div className="password-strength" role="status" aria-live="polite">
                <div className={`strength-bar strength-${getPasswordStrength(password)}`}>
                  <span></span><span></span><span></span>
                </div>
                <p className="file-name">
                  {getPasswordStrength(password) === 'strong' && (
                    <>
                      <ShieldCheck size={14} aria-hidden="true" />
                      <span>Strong password</span>
                    </>
                  )}
                  {getPasswordStrength(password) === 'medium' && (
                    <>
                      <ShieldAlert size={14} aria-hidden="true" />
                      <span>Medium strength — consider adding symbols or numbers</span>
                    </>
                  )}
                  {getPasswordStrength(password) === 'weak' && (
                    <>
                      <ShieldX size={14} aria-hidden="true" />
                      <span>Weak password</span>
                    </>
                  )}
                </p>
              </div>
            )}
            {password && !passwordError && (
              <p className="file-name">
                <Lock size={14} aria-hidden="true" />
                <span>File will be password-protected</span>
              </p>
            )}
          </div>

          {/* Capacity Indicator */}
          {image && (file || text) && (
            <CapacityIndicator
              carrierFile={image}
              hiddenFile={mode === 'file' ? file : null}
              hiddenText={mode === 'text' ? text : ''}
              mode="stego"
              password={password}
            />
          )}

          {error && <div className="error-message" role="alert">{error}</div>}

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
            {loading ? 'Hiding File...' : 'Hide File'}
          </button>
        </form>
      ) : (
        <div className="success-card">
          <div className="success-icon">
            <CheckCircle2 size={48} strokeWidth={1.75} aria-hidden="true" />
          </div>
          <h3>File Hidden Successfully!</h3>
          <p>Your file has been securely hidden in the image.</p>
          <button type="button" onClick={handleDownload} className="download-button">
            <Download size={16} aria-hidden="true" />
            <span>Download Image</span>
          </button>
          <button
            type="button"
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
