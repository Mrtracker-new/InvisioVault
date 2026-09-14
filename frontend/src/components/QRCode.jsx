import { useState } from 'react'
import { QrCode, Sparkles, ScanLine, Sliders, Lock, AlertTriangle, ShieldCheck, ShieldAlert, ShieldX, CheckCircle2, Download, Smartphone, Camera, Upload, RotateCcw, AlertCircle, Globe, Check, Copy, Info, Eye, EyeOff } from 'lucide-react'
import axios from 'axios'
import './QRCode.css'
import API_URL from '../config/api'
import { useQRScanner } from '../hooks/useQRScanner'
import FileDropzone from './FileDropzone'
import StepProgress from './StepProgress'
import ProcessingIndicator from './ProcessingIndicator'

const QR_GENERATE_STEPS = [
    { id: 1, label: 'Public Data' },
    { id: 2, label: 'Secret Payload' },
    { id: 3, label: 'Customization & Security' },
    { id: 4, label: 'Generate & Download' }
]

const QR_EXTRACT_STEPS = [
    { id: 1, label: 'Scan Method' },
    { id: 2, label: 'Security (Password)' },
    { id: 3, label: 'Scan & Results' }
]

function QRCode() {
    const [activeTab, setActiveTab] = useState('generate') // 'generate' or 'extract'
    const [scanMode, setScanMode] = useState('camera') // 'camera' or 'upload'

    // Generation state
    const [publicData, setPublicData] = useState('')
    const [secretText, setSecretText] = useState('')
    const [password, setPassword] = useState('')
    const [showPassword, setShowPassword] = useState(false)
    const [passwordError, setPasswordError] = useState('')
    const [fgColor, setFgColor] = useState('#000000')
    const [bgColor, setBgColor] = useState('#FFFFFF')
    const [scale, setScale] = useState(20) // Increased to 20 for better scannability
    const [logo, setLogo] = useState(null)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState('')
    const [success, setSuccess] = useState(false)
    const [downloadId, setDownloadId] = useState('')
    const [qrPreview, setQrPreview] = useState(null)

    // Scan/Extract state
    const [uploadedQR, setUploadedQR] = useState(null)
    const [extractPassword, setExtractPassword] = useState('')
    const [showExtractPassword, setShowExtractPassword] = useState(false)
    const [extractedData, setExtractedData] = useState(null)
    const [extractLoading, setExtractLoading] = useState(false)
    const [extractError, setExtractError] = useState('')
    const [cameraError, setCameraError] = useState('')
    const [copiedField, setCopiedField] = useState('')

    // Camera scanner with callbacks
    const isScanning = activeTab === 'extract' && scanMode === 'camera'

    const MIN_PASSWORD_LENGTH = 8

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

    const handleQRDetected = async ({ blob, rawQrData }) => {
        // QR detected from camera - now extract hidden data
        // rawQrData contains the decoded QR string from the client-side jsQR scan;
        // it is available for future use but the server re-derives it from the image.
        console.log('[QRCode Component] QR detected from camera, extracting data...', rawQrData)
        try {
            setExtractLoading(true)
            setExtractError('')

            const formData = new FormData()
            formData.append('image', blob, 'scanned-qr.png')

            if (extractPassword) {
                console.log('[QRCode Component] Using password for extraction')
                formData.append('password', extractPassword)
            }

            console.log('[QRCode Component] Sending to /api/qr/scan...')
            const response = await axios.post(`${API_URL}/api/qr/scan`, formData, {
                headers: {
                    'Content-Type': 'multipart/form-data'
                }
            })

            console.log('[QRCode Component] Extraction successful:', response.data)
            setExtractedData({
                publicData: response.data.publicData,
                secretData: response.data.secretData
            })
        } catch (err) {
            console.error('[QRCode Component] Extraction error:', err)
            const errorMsg = err.response?.data?.error || 'An error occurred while scanning the QR code'
            setExtractError(errorMsg)

            // Check if password is required
            if (err.response?.data?.passwordRequired) {
                setExtractError(errorMsg + ' Please enter the password and try again.')
            }
        } finally {
            setExtractLoading(false)
        }
    }

    const handleScanError = (err) => {
        // Map raw DOMException names to user-friendly messages
        let msg = 'Camera access failed.'
        if (err.name === 'NotAllowedError') {
            msg = 'Camera permission denied. Please allow camera access in your browser settings and try again.'
        } else if (err.name === 'NotFoundError') {
            msg = 'No camera found on this device.'
        } else if (err.name === 'NotReadableError') {
            msg = 'Camera is already in use by another application.'
        } else if (err.message && err.message.includes('HTTPS')) {
            msg = 'Camera requires a secure connection (HTTPS). You can still use \'Upload Image\' mode instead.'
        } else if (err.message) {
            msg = err.message
        }
        setCameraError(msg)
    }

    const { videoRef, canvasRef, error: scanError, isScanning: cameraActive, reset: resetScanner, boundingBox } = useQRScanner(
        isScanning,
        handleQRDetected,
        handleScanError
    )

    const handleGenerate = async (e) => {
        e.preventDefault()
        setError('')
        setSuccess(false)
        setQrPreview(null)

        if (!publicData.trim()) {
            setError('Please enter public data (URL or text) for the QR code')
            return
        }

        if (!secretText.trim()) {
            setError('Please enter secret text to hide')
            return
        }

        if (password && password.length < MIN_PASSWORD_LENGTH) {
            setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters long`)
            return
        }

        setLoading(true)

        try {
            const formData = new FormData()
            formData.append('public_data', publicData)
            formData.append('secret_text', secretText)
            formData.append('fg_color', fgColor)
            formData.append('bg_color', bgColor)
            formData.append('scale', scale)

            if (password) {
                formData.append('password', password)
            }

            if (logo) {
                formData.append('logo', logo)
            }

            const response = await axios.post(`${API_URL}/api/qr/generate`, formData, {
                headers: {
                    'Content-Type': 'multipart/form-data'
                }
            })

            setDownloadId(response.data.download_id)
            setQrPreview(`${API_URL}/api/qr/download/${response.data.download_id}`)
            setSuccess(true)
        } catch (err) {
            setError(err.response?.data?.error || 'An error occurred while generating the QR code')
        } finally {
            setLoading(false)
        }
    }

    const handleDownload = () => {
        const link = document.createElement('a')
        link.href = `${API_URL}/api/qr/download/${downloadId}`
        link.setAttribute('download', 'invisiovault_qrcode.png')
        document.body.appendChild(link)
        link.click()
        link.remove()
    }

    const handleExtract = async (e) => {
        e.preventDefault()
        setExtractError('')
        setExtractedData(null)

        if (!uploadedQR) {
            setExtractError('Please upload a QR code image')
            return
        }

        setExtractLoading(true)

        try {
            const formData = new FormData()
            formData.append('image', uploadedQR)

            if (extractPassword) {
                formData.append('password', extractPassword)
            }

            const response = await axios.post(`${API_URL}/api/qr/scan`, formData, {
                headers: {
                    'Content-Type': 'multipart/form-data'
                }
            })

            setExtractedData({
                publicData: response.data.publicData,
                secretData: response.data.secretData
            })
        } catch (err) {
            const errorMsg = err.response?.data?.error || 'An error occurred while scanning the QR code'
            setExtractError(errorMsg)

            // Check if password is required
            if (err.response?.data?.passwordRequired) {
                setExtractError(errorMsg + ' Please enter the password.')
            }
        } finally {
            setExtractLoading(false)
        }
    }

    const resetGenerate = () => {
        setSuccess(false)
        setDownloadId('')
        setQrPreview(null)
        setPublicData('')
        setSecretText('')
        setPassword('')
        setLogo(null)
        if (document.getElementById('logo-input')) {
            document.getElementById('logo-input').value = ''
        }
    }

    const resetExtract = () => {
        setUploadedQR(null)
        setExtractPassword('')
        setExtractedData(null)
        setExtractError('')
        setCameraError('')
        resetScanner()
        if (document.getElementById('uploaded-qr-input')) {
            document.getElementById('uploaded-qr-input').value = ''
        }
        if (document.getElementById('qr-upload')) {
            document.getElementById('qr-upload').value = ''
        }
    }

    const copyToClipboard = (text, type) => {
        navigator.clipboard.writeText(text)
        setCopiedField(type)
        setTimeout(() => setCopiedField(''), 2000)
    }

    const getGenerateStep = () => {
        if (success || loading) return 4
        if (publicData && secretText) return 3
        if (publicData) return 2
        return 1
    }

    const getExtractStep = () => {
        if (extractedData || extractLoading) return 3
        if (scanMode === 'upload' && uploadedQR) return 2
        if (scanMode === 'camera' && cameraActive) return 2
        return 1
    }

    const qrGenStages = [
        'Generating primary QR matrix...',
        'Encoding hidden steganographic payload...',
        logo ? 'Embedding centered logo watermark...' : 'Applying color matrices...',
        'Finalizing customized QR code...'
    ]

    const qrExtractStages = [
        'Detecting QR matrix patterns...',
        'Decoding public primary text...',
        extractPassword ? 'Decrypting embedded secret with password...' : 'Extracting hidden stego payload...',
        'Validating extracted data...'
    ]

    return (
        <div className="qr-code">
            <h2 style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
                <QrCode size={22} aria-hidden="true" />
                <span>QR Code Steganography</span>
            </h2>
            <p className="description">
                Generate customized QR codes with hidden messages, or scan to reveal secrets
            </p>

            <div className="tab-container-qr" role="tablist" aria-label="QR Code Mode">
                <button
                    id="qr-tab-generate"
                    role="tab"
                    aria-selected={activeTab === 'generate'}
                    aria-controls="qr-panel-generate"
                    className={`tab-qr ${activeTab === 'generate' ? 'active' : ''}`}
                    onClick={() => { setActiveTab('generate'); setError(''); setExtractError(''); }}
                >
                    <Sparkles size={16} aria-hidden="true" />
                    <span>Generate</span>
                </button>
                <button
                    id="qr-tab-extract"
                    role="tab"
                    aria-selected={activeTab === 'extract'}
                    aria-controls="qr-panel-extract"
                    className={`tab-qr ${activeTab === 'extract' ? 'active' : ''}`}
                    onClick={() => { setActiveTab('extract'); setError(''); setExtractError(''); }}
                >
                    <ScanLine size={16} aria-hidden="true" />
                    <span>Scan & Extract</span>
                </button>
            </div>

            {activeTab === 'generate' ? (
                <div id="qr-panel-generate" role="tabpanel" aria-labelledby="qr-tab-generate" className="qr-generate">
                    <StepProgress steps={QR_GENERATE_STEPS} currentStep={getGenerateStep()} />
                    {!success ? (
                        <form onSubmit={handleGenerate}>
                            <div className="form-group">
                                <label htmlFor="public-data">Public QR Data (visible when scanned)</label>
                                <input
                                    id="public-data"
                                    type="text"
                                    placeholder="e.g., https://yourwebsite.com or any text"
                                    value={publicData}
                                    onChange={(e) => setPublicData(e.target.value)}
                                    required
                                />
                                <small>This is what people see when they scan your QR code normally</small>
                            </div>

                            <div className="form-group">
                                <label htmlFor="secret-text">Secret Message (hidden)</label>
                                <textarea
                                    id="secret-text"
                                    placeholder="Type your secret message here... (e.g., password, API key, secret URL)"
                                    value={secretText}
                                    onChange={(e) => setSecretText(e.target.value)}
                                    rows="4"
                                    required
                                />
                                {secretText && <p className="char-count">Characters: {secretText.length}</p>}
                                <small>This will be hidden in the QR code using steganography</small>
                            </div>

                            <div className="customization-section">
                                <h3 style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}>
                                    <Sliders size={18} />
                                    <span>Customization</span>
                                </h3>

                                <div className="form-row">
                                    <div className="form-group-half">
                                        <label htmlFor="fg-color">Foreground Color</label>
                                        <div className="color-picker-wrapper">
                                            <input
                                                id="fg-color"
                                                type="color"
                                                value={fgColor}
                                                onChange={(e) => setFgColor(e.target.value)}
                                            />
                                            <span className="color-value">{fgColor}</span>
                                        </div>
                                    </div>

                                    <div className="form-group-half">
                                        <label htmlFor="bg-color">Background Color</label>
                                        <div className="color-picker-wrapper">
                                            <input
                                                id="bg-color"
                                                type="color"
                                                value={bgColor}
                                                onChange={(e) => setBgColor(e.target.value)}
                                            />
                                            <span className="color-value">{bgColor}</span>
                                        </div>
                                    </div>
                                </div>

                                <div className="form-group">
                                    <label htmlFor="scale">Size Scale: {scale} ({scale * 15}×{scale * 15} px)</label>
                                    <input
                                        id="scale"
                                        type="range"
                                        min="5"
                                        max="20"
                                        value={scale}
                                        onChange={(e) => setScale(parseInt(e.target.value))}
                                        aria-label="QR Code Size Scale"
                                        aria-valuemin="5"
                                        aria-valuemax="20"
                                        aria-valuenow={scale}
                                        aria-valuetext={`Scale size ${scale}`}
                                        disabled={loading}
                                    />
                                    <small>Adjust the QR code size (larger = higher capacity)</small>
                                </div>

                                <FileDropzone
                                    id="logo-input"
                                    label="Logo (Optional)"
                                    accept="image/png,image/jpeg,image/bmp"
                                    file={logo}
                                    onFileSelect={setLogo}
                                    onClear={() => setLogo(null)}
                                    helperText="Add a logo in the center of your QR code"
                                    compact
                                    disabled={loading}
                                />
                            </div>

                            <div className="form-group">
                                <label htmlFor="password-input" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                                    <span>Password (Optional)</span>
                                    <Lock size={14} style={{ opacity: 0.7 }} aria-hidden="true" />
                                </label>
                                <div className="password-input-wrapper">
                                    <input
                                        id="password-input"
                                        type={showPassword ? "text" : "password"}
                                        placeholder="Enter password to encrypt the secret (min. 8 chars)"
                                        value={password}
                                        onChange={handlePasswordChange}
                                        aria-describedby={passwordError ? 'qr-password-error' : undefined}
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
                                {passwordError && (
                                    <p id="qr-password-error" className="password-error-msg" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }} role="alert">
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
                                        <span>Secret will be password-protected</span>
                                    </p>
                                )}
                            </div>

                            {error && <div className="error-message" role="alert">{error}</div>}

                            <ProcessingIndicator
                                isActive={loading}
                                stages={qrGenStages}
                            />

                            <button
                                type="submit"
                                disabled={loading}
                                className="submit-button"
                                aria-busy={loading}
                                style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
                            >
                                {loading ? 'Generating QR Code...' : (
                                    <>
                                        <Sparkles size={16} aria-hidden="true" />
                                        <span>Generate QR Code</span>
                                    </>
                                )}
                            </button>
                        </form>
                    ) : (
                        <div className="success-card">
                            <div className="success-icon">
                                <CheckCircle2 size={48} strokeWidth={1.75} />
                            </div>
                            <h3>QR Code Generated Successfully!</h3>
                            {qrPreview && (
                                <div className="qr-preview">
                                    <img src={qrPreview} alt="Generated QR Code" />
                                    <div className="preview-hint">
                                        <p style={{ margin: '4px 0', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
                                            <Smartphone size={14} />
                                            <span>Scan with phone → Shows: {publicData}</span>
                                        </p>
                                        <p style={{ margin: '4px 0', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
                                            <ScanLine size={14} />
                                            <span>Scan with InvisioVault → Also reveals secret message</span>
                                        </p>
                                    </div>
                                </div>
                            )}
                            <button type="button" onClick={handleDownload} className="download-button">
                                <Download size={16} aria-hidden="true" />
                                <span>Download QR Code</span>
                            </button>
                            <button type="button" onClick={resetGenerate} className="new-button">
                                Create Another QR Code
                            </button>
                        </div>
                    )}
                </div>
            ) : (
                <div id="qr-panel-extract" role="tabpanel" aria-labelledby="qr-tab-extract" className="qr-extract">
                    <StepProgress steps={QR_EXTRACT_STEPS} currentStep={getExtractStep()} />
                    {!extractedData ? (
                        <div>
                            {/* Scan Mode Toggle */}
                            <div className="scan-mode-toggle" role="tablist" aria-label="Scan Mode">
                                <button
                                    id="scan-tab-camera"
                                    role="tab"
                                    aria-selected={scanMode === 'camera'}
                                    aria-controls="scan-panel-camera"
                                    type="button"
                                    className={`mode-btn ${scanMode === 'camera' ? 'active' : ''}`}
                                    onClick={() => setScanMode('camera')}
                                >
                                    <Camera size={16} aria-hidden="true" />
                                    <span>Camera Scan</span>
                                </button>
                                <button
                                    id="scan-tab-upload"
                                    role="tab"
                                    aria-selected={scanMode === 'upload'}
                                    aria-controls="scan-panel-upload"
                                    type="button"
                                    className={`mode-btn ${scanMode === 'upload' ? 'active' : ''}`}
                                    onClick={() => setScanMode('upload')}
                                >
                                    <Upload size={16} aria-hidden="true" />
                                    <span>Upload Image</span>
                                </button>
                            </div>

                            {scanMode === 'camera' ? (
                                <div id="scan-panel-camera" role="tabpanel" aria-labelledby="scan-tab-camera" className="camera-scanner">
                                    <div className="camera-container">
                                        <video ref={videoRef} autoPlay playsInline muted allow="camera" className="camera-video" />
                                        <canvas ref={canvasRef} style={{ display: 'none' }} />

                                        {/* Dynamic Bounding Box Overlay */}
                                        {cameraActive && boundingBox && videoRef.current && (
                                            <svg
                                                className="qr-overlay"
                                                viewBox={`0 0 ${videoRef.current.videoWidth} ${videoRef.current.videoHeight}`}
                                                style={{
                                                    position: 'absolute',
                                                    top: 0,
                                                    left: 0,
                                                    width: '100%',
                                                    height: '100%',
                                                    pointerEvents: 'none',
                                                    zIndex: 10
                                                }}
                                            >
                                                <path
                                                    d={`M${boundingBox.topLeftCorner.x},${boundingBox.topLeftCorner.y} L${boundingBox.topRightCorner.x},${boundingBox.topRightCorner.y} L${boundingBox.bottomRightCorner.x},${boundingBox.bottomRightCorner.y} L${boundingBox.bottomLeftCorner.x},${boundingBox.bottomLeftCorner.y} Z`}
                                                    fill="rgba(0, 255, 0, 0.2)"
                                                    stroke="#00FF00"
                                                    strokeWidth="4"
                                                    strokeLinejoin="round"
                                                />
                                            </svg>
                                        )}

                                        {!cameraActive && !scanError && (
                                            <div className="camera-placeholder">
                                                <p style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                                    <Camera size={18} />
                                                    <span>Starting camera...</span>
                                                </p>
                                            </div>
                                        )}

                                        {cameraActive && !boundingBox && (
                                            <div className="scanning-overlay">
                                                <div className="scan-frame"></div>
                                                <p className="scan-hint" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                                                    <ScanLine size={14} />
                                                    <span>Point your camera at a QR code</span>
                                                </p>
                                            </div>
                                        )}
                                    </div>

                                    {(scanError || cameraError) && (
                                        <div className="error-message" role="alert" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '8px' }}>
                                            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                                <AlertCircle size={16} />
                                                <span>{cameraError || scanError}</span>
                                            </span>
                                            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                                                <button
                                                    type="button"
                                                    className="mode-btn"
                                                    style={{ fontSize: '0.8rem', padding: '6px 12px' }}
                                                    onClick={() => { setCameraError(''); resetScanner() }}
                                                >
                                                    <RotateCcw size={14} />
                                                    <span>Try Again</span>
                                                </button>
                                                <button
                                                    type="button"
                                                    className="mode-btn"
                                                    style={{ fontSize: '0.8rem', padding: '6px 12px' }}
                                                    onClick={() => setScanMode('upload')}
                                                >
                                                    <Upload size={14} />
                                                    <span>Switch to Upload</span>
                                                </button>
                                            </div>
                                        </div>
                                    )}

                                    {extractLoading && (
                                        <div className="scanning-status">
                                            <p style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}>
                                                <ScanLine size={16} />
                                                <span>Extracting hidden data...</span>
                                            </p>
                                        </div>
                                    )}

                                    {extractError && !scanError && !cameraError && (
                                        <div className="error-message" role="alert">{extractError}</div>
                                    )}

                                    {/* Password input for camera mode */}
                                    <div className="form-group" style={{ marginTop: '1rem' }}>
                                        <label htmlFor="camera-password">Password (if encrypted)</label>
                                        <div className="password-input-wrapper">
                                            <input
                                                id="camera-password"
                                                type={showExtractPassword ? "text" : "password"}
                                                placeholder="Enter password before scanning"
                                                value={extractPassword}
                                                onChange={(e) => setExtractPassword(e.target.value)}
                                            />
                                            {extractPassword && (
                                                <button
                                                    type="button"
                                                    className="password-toggle"
                                                    onClick={() => setShowExtractPassword(!showExtractPassword)}
                                                    aria-label={showExtractPassword ? "Hide password" : "Show password"}
                                                    aria-pressed={showExtractPassword}
                                                >
                                                    {showExtractPassword ? (
                                                        <EyeOff size={18} aria-hidden="true" />
                                                    ) : (
                                                        <Eye size={18} aria-hidden="true" />
                                                    )}
                                                </button>
                                            )}
                                        </div>
                                        <small>Enter password before scanning if your QR is encrypted</small>
                                    </div>
                                </div>
                            ) : (
                                <form id="scan-panel-upload" role="tabpanel" aria-labelledby="scan-tab-upload" onSubmit={handleExtract}>
                                    <div className="form-group">
                                        <FileDropzone
                                            id="uploaded-qr-input"
                                            label="Upload QR Code Image"
                                            accept="image/png,image/jpeg,image/bmp"
                                            file={uploadedQR}
                                            onFileSelect={(f) => { setUploadedQR(f); setExtractError(''); }}
                                            onClear={() => setUploadedQR(null)}
                                            helperText="Select or drag a saved QR code image to extract hidden secret"
                                            required
                                            disabled={extractLoading}
                                        />
                                    </div>

                                    <div className="form-group">
                                        <label htmlFor="extract-password">Password (if encrypted)</label>
                                        <div className="password-input-wrapper">
                                            <input
                                                id="extract-password"
                                                type={showExtractPassword ? "text" : "password"}
                                                placeholder="Enter password (leave empty if not encrypted)"
                                                value={extractPassword}
                                                onChange={(e) => setExtractPassword(e.target.value)}
                                            />
                                            {extractPassword && (
                                                <button
                                                    type="button"
                                                    className="password-toggle"
                                                    onClick={() => setShowExtractPassword(!showExtractPassword)}
                                                    aria-label={showExtractPassword ? "Hide password" : "Show password"}
                                                    aria-pressed={showExtractPassword}
                                                >
                                                    {showExtractPassword ? (
                                                        <EyeOff size={18} aria-hidden="true" />
                                                    ) : (
                                                        <Eye size={18} aria-hidden="true" />
                                                    )}
                                                </button>
                                            )}
                                        </div>
                                    </div>

                                    {extractError && <div className="error-message" role="alert">{extractError}</div>}

                                    <ProcessingIndicator
                                        isActive={extractLoading}
                                        stages={qrExtractStages}
                                    />

                                    {!extractLoading && (
                                        <button
                                            type="submit"
                                            disabled={extractLoading || !uploadedQR}
                                            className="submit-button"
                                            style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
                                        >
                                            <ScanLine size={16} />
                                            <span>Scan & Extract</span>
                                        </button>
                                    )}
                                </form>
                            )}
                        </div>
                    ) : (
                        <div className="extracted-data">
                            <div className="success-icon">
                                <CheckCircle2 size={48} strokeWidth={1.75} />
                            </div>
                            <h3>Data Extracted Successfully!</h3>

                            <div className="data-section">
                                <h4 style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <Globe size={16} />
                                    <span>Public Data (Visible):</span>
                                </h4>
                                <div className="data-box">
                                    <p>{extractedData.publicData}</p>
                                    <button
                                        type="button"
                                        className="copy-btn"
                                        onClick={() => copyToClipboard(extractedData.publicData, 'Public data')}
                                        aria-label="Copy public data to clipboard"
                                    >
                                        {copiedField === 'Public data' ? (
                                            <>
                                                <Check size={14} />
                                                <span>Copied!</span>
                                            </>
                                        ) : (
                                            <>
                                                <Copy size={14} />
                                                <span>Copy</span>
                                            </>
                                        )}
                                    </button>
                                </div>
                            </div>

                            {extractedData.secretData ? (
                                <div className="data-section">
                                    <h4 style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                        <Lock size={16} />
                                        <span>Hidden Secret Message:</span>
                                    </h4>
                                    <div className="data-box secret">
                                        <p>{extractedData.secretData}</p>
                                        <button
                                            type="button"
                                            className="copy-btn"
                                            onClick={() => copyToClipboard(extractedData.secretData, 'Secret data')}
                                            aria-label="Copy secret message to clipboard"
                                        >
                                            {copiedField === 'Secret data' ? (
                                                <>
                                                    <Check size={14} />
                                                    <span>Copied!</span>
                                                </>
                                            ) : (
                                                <>
                                                    <Copy size={14} />
                                                    <span>Copy</span>
                                                </>
                                            )}
                                        </button>
                                    </div>
                                </div>
                            ) : (
                                <div className="data-section">
                                    <h4 style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                        <Lock size={16} />
                                        <span>Hidden Secret Message:</span>
                                    </h4>
                                    <div className="data-box" style={{ background: 'var(--bg-elevated)', borderStyle: 'dashed' }}>
                                        <p style={{ color: 'var(--text-tertiary)', fontStyle: 'italic', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                            <Info size={16} style={{ flexShrink: 0 }} />
                                            <span>No hidden data found. This appears to be a regular QR code without steganographic content.</span>
                                        </p>
                                    </div>
                                    <small style={{ display: 'block', marginTop: 'var(--space-2)', color: 'var(--text-tertiary)' }}>
                                        Only QR codes generated with InvisioVault contain hidden messages.
                                    </small>
                                </div>
                            )}

                            <button type="button" onClick={resetExtract} className="new-button">
                                Scan Another QR Code
                            </button>
                        </div>
                    )}
                </div>
            )}
        </div>
    )
}

export default QRCode
