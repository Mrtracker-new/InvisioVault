import { useState } from 'react'
import { Layers, PackagePlus, FolderDown, Lock, AlertTriangle, ShieldCheck, ShieldAlert, ShieldX, BarChart3, Info, CheckCircle2, Download } from 'lucide-react'
import axios from 'axios'
import './Polyglot.css'
import API_URL from '../config/api'
import { getApiErrorMessage } from '../utils/apiError'
import FileDropzone from './FileDropzone'
import StepProgress from './StepProgress'
import ProcessingIndicator from './ProcessingIndicator'

const CREATE_STEPS = [
  { id: 1, label: 'Carrier File' },
  { id: 2, label: 'File to Hide' },
  { id: 3, label: 'Security & Config' },
  { id: 4, label: 'Create & Download' }
]

const EXTRACT_STEPS = [
  { id: 1, label: 'Select Polyglot' },
  { id: 2, label: 'Security (Password)' },
  { id: 3, label: 'Extract File' }
]

function Polyglot() {
  const [mode, setMode] = useState('create') // 'create' or 'extract'
  const [carrierFile, setCarrierFile] = useState(null)
  const [fileToHide, setFileToHide] = useState(null)
  const [polyglotFile, setPolyglotFile] = useState(null)
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [passwordError, setPasswordError] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const [extractSuccess, setExtractSuccess] = useState('')
  const [downloadId, setDownloadId] = useState('')

  const MIN_PASSWORD_LENGTH = 8

  const getCreateStep = () => {
    if (success || loading) return 4
    if (carrierFile && fileToHide) return 3
    if (carrierFile) return 2
    return 1
  }

  const getExtractStep = () => {
    if (extractSuccess || loading) return 3
    if (polyglotFile) return 2
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

  const handleCreate = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess(false)

    if (!carrierFile || !fileToHide) {
      setError('Please select both carrier file and file to hide')
      return
    }

    if (password && password.length < MIN_PASSWORD_LENGTH) {
      setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters long`)
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
    } catch (err) {
      setError(err.response?.data?.error || 'An error occurred while creating the polyglot file')
    } finally {
      setLoading(false)
    }
  }

  const handleExtract = async (e) => {
    e.preventDefault()
    setError('')
    setExtractSuccess('')

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
      setExtractSuccess('File extracted and downloaded successfully!')
      setTimeout(() => setExtractSuccess(''), 4000)
    } catch (err) {
      // responseType is 'blob', so the error body is a Blob that must be
      // parsed to recover the server's message (e.g. "Incorrect password")
      setError(await getApiErrorMessage(err, 'An error occurred while extracting the file'))
    } finally {
      setLoading(false)
    }
  }

  const handleDownload = () => {
    const link = document.createElement('a')
    link.href = `${API_URL}/api/polyglot/download/${downloadId}`
    const ext = downloadId && downloadId.includes('.') ? downloadId.slice(downloadId.lastIndexOf('.')) : ''
    link.setAttribute('download', `invisiovault_polyglot${ext}`)
    document.body.appendChild(link)
    link.click()
    link.remove()
  }

  const createStages = [
    'Validating carrier file structure...',
    'Compressing payload into archive...',
    password ? 'Encrypting archive with password...' : 'Packaging payload...',
    'Merging polyglot file streams...',
    'Finalizing polyglot file...'
  ]

  const extractStages = [
    'Reading polyglot file headers...',
    'Locating embedded archive boundary...',
    password ? 'Verifying decryption password...' : 'Extracting archive payload...',
    'Recovering original file...'
  ]

  return (
    <div className="polyglot">
      <h2>
        <Layers size={22} style={{ display: 'inline-block', verticalAlign: 'middle', marginRight: '8px' }} aria-hidden="true" />
        <span>Polyglot File Hiding</span>
      </h2>
      <p className="description">
        Create polyglot files by appending hidden data to any carrier file. The carrier file remains functional while hiding your secret data.
      </p>

      {/* Sub-mode navigation with accessible role=tablist */}
      <div className="mode-selector" role="tablist" aria-label="Polyglot actions">
        <button
          type="button"
          id="polyglot-tab-create"
          role="tab"
          aria-selected={mode === 'create'}
          aria-controls="polyglot-panel-create"
          className={`mode-btn ${mode === 'create' ? 'active' : ''}`}
          onClick={() => { setMode('create'); setError(''); setSuccess(false); }}
        >
          <PackagePlus size={16} aria-hidden="true" />
          <span>Create Polyglot</span>
        </button>
        <button
          type="button"
          id="polyglot-tab-extract"
          role="tab"
          aria-selected={mode === 'extract'}
          aria-controls="polyglot-panel-extract"
          className={`mode-btn ${mode === 'extract' ? 'active' : ''}`}
          onClick={() => { setMode('extract'); setError(''); setSuccess(false); }}
        >
          <FolderDown size={16} aria-hidden="true" />
          <span>Extract from Polyglot</span>
        </button>
      </div>

      {mode === 'create' ? (
        <div id="polyglot-panel-create" role="tabpanel" aria-labelledby="polyglot-tab-create">
          {/* Step Progress for Polyglot Creation */}
          <StepProgress steps={CREATE_STEPS} currentStep={getCreateStep()} />

          {!success ? (
            <form onSubmit={handleCreate}>
              <FileDropzone
                id="carrier-input"
                label="Select Carrier File (Any Format)"
                file={carrierFile}
                onFileSelect={(f) => { setCarrierFile(f); setError(''); }}
                onClear={() => setCarrierFile(null)}
                helperText="Carrier file stays completely functional (Image, PDF, ZIP, MP4, etc.)"
                required
                disabled={loading}
              />

              <FileDropzone
                id="hide-input"
                label="Select File to Hide"
                file={fileToHide}
                onFileSelect={(f) => { setFileToHide(f); setError(''); }}
                onClear={() => setFileToHide(null)}
                helperText="Any file type to be zipped and appended as hidden data"
                required
                disabled={loading}
              />

              <div className="form-group">
                <label htmlFor="polyglot-password-input" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                  <span>Password (Optional)</span>
                  <Lock size={14} style={{ opacity: 0.7 }} aria-hidden="true" />
                </label>
                <div className="password-input-wrapper">
                  <input
                    id="polyglot-password-input"
                    type={showPassword ? "text" : "password"}
                    placeholder="Enter password to protect the ZIP (min. 8 chars)"
                    value={password}
                    onChange={handlePasswordChange}
                    aria-describedby={passwordError ? 'polyglot-password-error' : undefined}
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
                          <path d="M1 12s4-8 11-8 11 8-4 8-11 8-11-8-11-8z"></path>
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
                  <p id="polyglot-password-error" className="password-error-msg" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }} role="alert">
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
                    <span>ZIP will be password-protected</span>
                  </p>
                )}
              </div>

              {/* Informational Size Calculation */}
              {carrierFile && fileToHide && (
                <div className="info-box" style={{ marginBottom: '1rem' }}>
                  <h4>
                    <BarChart3 size={16} aria-hidden="true" />
                    <span>File Size Information</span>
                  </h4>
                  <p style={{ margin: '0.5rem 0' }}>
                    <strong>Carrier:</strong> {(carrierFile.size / 1024).toFixed(2)} KB
                  </p>
                  <p style={{ margin: '0.5rem 0' }}>
                    <strong>File to Hide:</strong> {(fileToHide.size / 1024).toFixed(2)} KB
                  </p>
                  <p style={{ margin: '0.5rem 0', fontSize: '0.85rem', opacity: '0.8', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <Info size={14} style={{ flexShrink: 0 }} aria-hidden="true" />
                    <span>Final polyglot size will be approximately {((carrierFile.size + fileToHide.size) / 1024).toFixed(2)} KB</span>
                  </p>
                </div>
              )}

              {error && <div className="error-message" role="alert">{error}</div>}

              {/* Staged Micro-Processing Indicator */}
              <ProcessingIndicator
                isActive={loading}
                stages={createStages}
              />

              <button
                type="submit"
                disabled={loading}
                className="submit-button"
                aria-busy={loading}
              >
                {loading ? 'Creating Polyglot...' : 'Create Polyglot'}
              </button>

              <div className="info-box">
                <h4>
                  <Info size={16} aria-hidden="true" />
                  <span>How it works</span>
                </h4>
                <ul>
                  <li>Your file will be zipped and appended to the carrier file</li>
                  <li>The carrier file remains fully functional in standard viewers</li>
                  <li>Works with images, PDFs, videos, executables, and archives</li>
                </ul>
              </div>
            </form>
          ) : (
            <div className="success-card">
              <div className="success-icon">
                <CheckCircle2 size={48} strokeWidth={1.75} aria-hidden="true" />
              </div>
              <h3>Polyglot Created Successfully!</h3>
              <p>Your file has been hidden inside the carrier file.</p>
              <button type="button" onClick={handleDownload} className="download-button">
                <Download size={16} aria-hidden="true" />
                <span>Download Polyglot File</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  setSuccess(false)
                  setDownloadId('')
                }}
                className="new-button"
              >
                Create Another
              </button>
            </div>
          )}
        </div>
      ) : (
        <div id="polyglot-panel-extract" role="tabpanel" aria-labelledby="polyglot-tab-extract">
          {/* Step Progress for Polyglot Extraction */}
          <StepProgress steps={EXTRACT_STEPS} currentStep={getExtractStep()} />

          <form onSubmit={handleExtract}>
            <FileDropzone
              id="polyglot-input"
              label="Select Polyglot File"
              file={polyglotFile}
              onFileSelect={(f) => { setPolyglotFile(f); setError(''); }}
              onClear={() => setPolyglotFile(null)}
              helperText="Upload the polyglot carrier file to extract hidden data"
              required
              disabled={loading}
            />

            <div className="form-group">
              <label htmlFor="extract-polyglot-password" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                <span>Password (Optional)</span>
                <Lock size={14} style={{ opacity: 0.7 }} aria-hidden="true" />
              </label>
              <div className="password-input-wrapper">
                <input
                  id="extract-polyglot-password"
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
            </div>

            {extractSuccess && (
              <div className="success-message" role="status" aria-live="polite" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <CheckCircle2 size={16} style={{ flexShrink: 0 }} aria-hidden="true" />
                <span>{extractSuccess}</span>
              </div>
            )}
            {error && <div className="error-message" role="alert">{error}</div>}

            {/* Staged Micro-Processing Indicator */}
            <ProcessingIndicator
              isActive={loading}
              stages={extractStages}
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
                <li>Upload a file created with InvisioVault Polyglot</li>
                <li>The hidden file will be extracted and downloaded</li>
                <li>The carrier file is not modified or harmed in the process</li>
              </ul>
            </div>
          </form>
        </div>
      )}
    </div>
  )
}

export default Polyglot
