import { useState, useRef } from 'react'
import { QrCode, Sparkles, ScanLine, Sliders, Lock, AlertTriangle, ShieldCheck, ShieldAlert, ShieldX, CheckCircle2, Download, Smartphone, Camera, Upload, RotateCcw, AlertCircle, Globe, Check, Copy, Info, Eye, EyeOff, Zap } from 'lucide-react'
import axios from 'axios'
import './QRCode.css'
import API_URL from '../config/api'
import { getApiErrorMessage } from '../utils/apiError'
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
    const [scanMode, setScanMode] = useState('upload') // 'upload' (recommended for visual stego) or 'camera'

    // Web Audio API Context (instantiated and resumed during user gesture to satisfy iOS Safari)
    const audioCtxRef = useRef(null)

    const initAudioContext = () => {
        try {
            const AudioCtx = window.AudioContext || window.webkitAudioContext
            if (!AudioCtx) return null
            if (!audioCtxRef.current) {
                audioCtxRef.current = new AudioCtx()
            }
            if (audioCtxRef.current.state === 'suspended') {
                audioCtxRef.current.resume()
            }
            return audioCtxRef.current
        } catch (e) {
            console.debug('[Audio] Web Audio init error:', e)
            return null
        }
    }

    const playSuccessChime = () => {
        try {
            const ctx = audioCtxRef.current || initAudioContext()
            if (!ctx) return
            if (ctx.state === 'suspended') {
                ctx.resume()
            }
            const now = ctx.currentTime
            // Two-tone harmonic chime: 880 Hz (A5) -> 1320 Hz (E6) with exponential decay
            const osc1 = ctx.createOscillator()
            const osc2 = ctx.createOscillator()
            const gain = ctx.createGain()

            osc1.type = 'sine'
            osc1.frequency.setValueAtTime(880, now)
            osc1.frequency.setValueAtTime(1320, now + 0.08)

            osc2.type = 'triangle'
            osc2.frequency.setValueAtTime(880 * 2, now)
            osc2.frequency.setValueAtTime(1320 * 2, now + 0.08)

            gain.gain.setValueAtTime(0.001, now)
            gain.gain.exponentialRampToValueAtTime(0.25, now + 0.02)
            gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.35)

            osc1.connect(gain)
            osc2.connect(gain)
            gain.connect(ctx.destination)

            osc1.start(now)
            osc2.start(now)
            osc1.stop(now + 0.35)
            osc2.stop(now + 0.35)
        } catch (err) {
            console.debug('[Audio] Could not play chime:', err)
        }
    }

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
    const [downloading, setDownloading] = useState(false)
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
    const [pendingScan, setPendingScan] = useState(null)
    // Two separate retry counters for different failure modes:
    //   magicFoundRetriesRef: PAYLOAD_DECODE_FAILED (magic header present, body RS-decode failed).
    //     Allow up to 6 retries — stego QR detected, just needs a sharper frame.
    //   noSecretRetriesRef: no magic found at all (regular QR or too blurry).
    //     Keep at 3, since this likely means no hidden data.
    const magicFoundRetriesRef = useRef(0)
    const noSecretRetriesRef = useRef(0)

    // Camera scanner state: Keep camera active while on camera tab without extracted data,
    // but pause frame processing if a scan is pending password entry or in-flight.
    const isCameraActive = activeTab === 'extract' && scanMode === 'camera' && !extractedData
    const isScannerPaused = Boolean(pendingScan || extractLoading)

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

    const handleQRDetected = async ({ blob, rawQrData, corners, version, metrics }) => {
        if (pendingScan || extractLoading) {
            console.log('[QRCode Component] Camera detection ignored because scan is pending password or in-flight.')
            return
        }

        console.log('[QRCode Component] QR detected from camera, extracting data...', {
            rawQrData,
            corners,
            version,
            metrics
        })
        try {
            setExtractLoading(true)
            setExtractError('')

            const formData = new FormData()
            formData.append('image', blob, 'scanned-qr.png')

            if (rawQrData) {
                formData.append('raw_qr_data', rawQrData)
            }

            if (corners) {
                formData.append('corners', JSON.stringify(corners))
            }

            if (version !== undefined && version !== null) {
                formData.append('version', String(version))
            }

            if (extractPassword) {
                console.log('[QRCode Component] Using password for extraction')
                formData.append('password', extractPassword)
            }

            console.log('[QRCode Component] Sending to /api/qr/scan with fields:', {
                rawQrData,
                version,
                corners,
                blobType: blob?.type,
                blobSize: blob?.size,
            })
            const response = await axios.post(`${API_URL}/api/qr/scan`, formData, {
                headers: {
                    'Content-Type': 'multipart/form-data'
                }
            })

            console.log('[QRCode Component] Extraction response:', {
                cameraScanId: response.data.cameraScanId,
                publicData: response.data.publicData,
                hasSecret: !!response.data.secretData,
                debug: response.data.debug
            })

            // If the user has entered a password beforehand, but this particular camera frame
            // did not decode secret data (e.g. optical blur), continue scanning rather than
            // prematurely locking the UI into "no hidden data".
            if (extractPassword && !response.data.secretData) {
                console.log('[QRCode Component] Password provided but frame did not yield secret, continuing scan...')
                setExtractError('Scanning for encrypted secret... Please hold camera steady.')
                return
            }

            // On live camera streams, allow up to 3 retry frames if no secret was detected yet,
            // giving the camera focus and sensor auto-exposure a moment to settle.
            if (!response.data.secretData && scanMode === 'camera' && noSecretRetriesRef.current < 3) {
                noSecretRetriesRef.current += 1
                console.log(`[QRCode Component] Frame did not yield secret, retrying (${noSecretRetriesRef.current}/3)...`)
                setExtractError('Scanning for hidden message... Please hold camera steady.')
                return
            }

            noSecretRetriesRef.current = 0
            magicFoundRetriesRef.current = 0
            setPendingScan(null)
            setExtractedData({
                publicData: response.data.publicData,
                secretData: response.data.secretData
            })
            // Physical reward feedback: Web Audio chime & haptic vibration
            playSuccessChime()
            if (typeof navigator !== 'undefined' && navigator.vibrate) {
                try {
                    navigator.vibrate(50)
                } catch (e) {}
            }
        } catch (err) {
            const scanId = err.response?.data?.cameraScanId || 'unknown'
            const failureReason = err.response?.data?.failureReason
            const isPwdRequired = !!err.response?.data?.passwordRequired
            console.error(`[QRCode Component] Extraction error [${scanId}] reason=${failureReason}:`, err)

            // PAYLOAD_DECODE_FAILED means the magic header was found but body RS-decode failed
            // due to optical distortion in this particular frame.  Auto-retry on the next frame
            // (with fast cooldown so the user doesn't wait 3 s) rather than surfacing a hard error.
            if (!isPwdRequired && failureReason === 'PAYLOAD_DECODE_FAILED' && scanMode === 'camera' && magicFoundRetriesRef.current < 6) {
                magicFoundRetriesRef.current += 1
                console.log(`[QRCode Component] Body decode failed (optical noise), retrying (${magicFoundRetriesRef.current}/6)...`)
                setExtractError('Hidden message detected — please hold camera steady for a clearer frame.')
                // Fast cooldown: let a new frame be dispatched after 1.2 s instead of 3 s
                clearCooldown(true)
                return
            }

            noSecretRetriesRef.current = 0
            magicFoundRetriesRef.current = 0
            if (isPwdRequired) {
                setPendingScan({ blob, rawQrData, corners, version })
                setExtractError('Encrypted secret detected! Please enter the password below and click Unlock.')
            } else {
                const errorMsg = err.response?.data?.error || 'An error occurred while scanning the QR code'
                setExtractError(errorMsg)
            }
        } finally {
            setExtractLoading(false)
        }
    }

    const handleUnlockPendingScan = async (e) => {
        if (e) e.preventDefault()
        initAudioContext()
        if (!pendingScan) return
        if (!extractPassword) {
            setExtractError('Please enter the password to unlock this QR code')
            return
        }

        try {
            setExtractLoading(true)
            setExtractError('')

            const formData = new FormData()
            formData.append('image', pendingScan.blob, 'scanned-qr.png')
            if (pendingScan.rawQrData) {
                formData.append('raw_qr_data', pendingScan.rawQrData)
            }
            if (pendingScan.corners) {
                formData.append('corners', JSON.stringify(pendingScan.corners))
            }
            if (pendingScan.version !== undefined && pendingScan.version !== null) {
                formData.append('version', String(pendingScan.version))
            }
            formData.append('password', extractPassword)

            console.log('[QRCode Component] Unlocking pending scan with password...')
            const response = await axios.post(`${API_URL}/api/qr/scan`, formData, {
                headers: {
                    'Content-Type': 'multipart/form-data'
                }
            })

            setPendingScan(null)
            setExtractedData({
                publicData: response.data.publicData,
                secretData: response.data.secretData
            })
            // Physical reward feedback on successful unlock
            playSuccessChime()
            if (typeof navigator !== 'undefined' && navigator.vibrate) {
                try {
                    navigator.vibrate(50)
                } catch (e) {}
            }
        } catch (err) {
            console.error('[QRCode Component] Unlock error:', err)
            const errorMsg = err.response?.data?.error || 'Incorrect password or failed to unlock secret'
            setExtractError(errorMsg)
            // Note: Keep pendingScan intact so the user can re-try typing their password!
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

    const {
        videoRef,
        canvasRef,
        error: scanError,
        isScanning: cameraActive,
        reset: resetScanner,
        boundingBox,
        stabilityState,
        clearCooldown,
        antiMoire,
        toggleAntiMoire,
        torchSupported,
        torchOn,
        toggleTorch,
    } = useQRScanner(
        isCameraActive,
        handleQRDetected,
        handleScanError,
        isScannerPaused
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
            formData.append('method', 'visual')

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

    const handleDownload = async () => {
        if (!downloadId || downloading) return
        setDownloading(true)
        setError('')
        try {
            const response = await axios.get(`${API_URL}/api/qr/download/${downloadId}`, {
                responseType: 'blob'
            })
            const url = window.URL.createObjectURL(new Blob([response.data]))
            const link = document.createElement('a')
            link.href = url
            link.setAttribute('download', 'invisiovault_qrcode.png')
            document.body.appendChild(link)
            link.click()
            link.remove()
            window.URL.revokeObjectURL(url)
        } catch (err) {
            setError(await getApiErrorMessage(err, 'Failed to download QR code'))
        } finally {
            setDownloading(false)
        }
    }

    const handleVerifyInExtractor = async () => {
        initAudioContext()
        if (!downloadId) return
        try {
            const response = await axios.get(`${API_URL}/api/qr/download/${downloadId}`, {
                responseType: 'blob'
            })
            const file = new File([response.data], 'invisiovault_qrcode.png', { type: 'image/png' })
            setUploadedQR(file)
            setExtractPassword(password)
            setActiveTab('extract')
            setScanMode('upload')
            setExtractedData(null)
            setExtractError('')
        } catch (err) {
            setError(await getApiErrorMessage(err, 'Failed to load QR code for verification'))
        }
    }

    const handleExtract = async (e) => {
        e.preventDefault()
        initAudioContext()
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
            playSuccessChime()
            if (typeof navigator !== 'undefined' && navigator.vibrate) {
                try {
                    navigator.vibrate(50)
                } catch (e) {}
            }
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
        setPendingScan(null)
        magicFoundRetriesRef.current = 0
        noSecretRetriesRef.current = 0
        if (clearCooldown) clearCooldown()
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
                    onClick={() => { initAudioContext(); setActiveTab('extract'); setError(''); setExtractError(''); }}
                >
                    <ScanLine size={16} aria-hidden="true" />
                    <span>Scan & Extract</span>
                </button>
            </div>

            {activeTab === 'generate' ? (
                <div id="qr-panel-generate" role="tabpanel" aria-labelledby="qr-tab-generate" className="qr-generate">
                    <StepProgress steps={QR_GENERATE_STEPS} currentStep={getGenerateStep()} isComplete={success} />
                    {!success ? (
                        <form onSubmit={handleGenerate}>
                            <div className="form-group">
                                <label htmlFor="public-data">Public URL</label>
                                <input
                                    id="public-data"
                                    type="text"
                                    placeholder="https://example.com"
                                    value={publicData}
                                    onChange={(e) => setPublicData(e.target.value)}
                                    required
                                />
                                <small>The URL a normal phone camera will open.</small>
                            </div>

                            <div className="form-group">
                                <label htmlFor="secret-text">Secret Message</label>
                                <textarea
                                    id="secret-text"
                                    placeholder="Type your secret message here... (e.g., password, API key, confidential note)"
                                    value={secretText}
                                    onChange={(e) => setSecretText(e.target.value)}
                                    rows="4"
                                    required
                                />
                                {secretText && <p className="char-count">Characters: {secretText.length}</p>}
                                <small>The hidden message visible only through InvisioVault.</small>
                            </div>

                            <div className="form-group">
                                <label>Steganography Mode</label>
                                <div className="method-card active" style={{ cursor: 'default' }}>
                                    <div className="method-card-header">
                                        <EyeOff size={16} style={{ color: 'var(--accent-success)' }} />
                                        <span>Stealth Visual</span>
                                        <span className="method-badge-rec">Recommended</span>
                                    </div>
                                    <p className="method-card-desc">
                                        Normal camera → opens your Public URL<br />
                                        InvisioVault → reveals your hidden secret
                                    </p>
                                </div>
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
                                <CheckCircle2 size={48} strokeWidth={1.75} color="var(--accent-success)" />
                            </div>
                            <h3>QR Code Generated Successfully!</h3>
                            {qrPreview && (
                                <div className="qr-preview">
                                    <img src={qrPreview} alt="Generated QR Code" />
                                    <div className="preview-hint">
                                        <p>
                                            <Smartphone size={14} aria-hidden="true" />
                                            <span>Normal camera opens:</span>
                                            <span className="preview-url-badge">{publicData}</span>
                                        </p>
                                        <p>
                                            <ScanLine size={14} aria-hidden="true" />
                                            <span>InvisioVault reveals hidden secret (Camera Scan or Upload)</span>
                                        </p>
                                    </div>
                                </div>
                            )}
                            {error && (
                                <div className="error-message" role="alert" style={{ marginBottom: '1rem' }}>
                                    {error}
                                </div>
                            )}
                            <div className="button-group-row">
                                <button type="button" onClick={handleDownload} disabled={downloading} className="download-button">
                                    <Download size={16} aria-hidden="true" />
                                    <span>{downloading ? 'Downloading...' : 'Download QR Code'}</span>
                                </button>
                                <button
                                    type="button"
                                    onClick={handleVerifyInExtractor}
                                    className="verify-button"
                                >
                                    <ScanLine size={16} aria-hidden="true" />
                                    <span>Verify in Extractor</span>
                                </button>
                            </div>
                            <div style={{ marginTop: 'var(--space-4)', display: 'flex', justifyContent: 'center' }}>
                                <button type="button" onClick={resetGenerate} className="new-button">
                                    Create Another QR Code
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            ) : (
                <div id="qr-panel-extract" role="tabpanel" aria-labelledby="qr-tab-extract" className="qr-extract">
                    <StepProgress steps={QR_EXTRACT_STEPS} currentStep={getExtractStep()} isComplete={Boolean(extractedData)} />
                    {!extractedData ? (
                        <div>
                            {/* Scan Mode Toggle */}
                            <div className="scan-mode-toggle" role="tablist" aria-label="Scan Mode">
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
                                <button
                                    id="scan-tab-camera"
                                    role="tab"
                                    aria-selected={scanMode === 'camera'}
                                    aria-controls="scan-panel-camera"
                                    type="button"
                                    className={`mode-btn ${scanMode === 'camera' ? 'active' : ''}`}
                                    onClick={() => { initAudioContext(); setScanMode('camera'); }}
                                >
                                    <Camera size={16} aria-hidden="true" />
                                    <span>Camera Scan</span>
                                </button>
                            </div>

                            {scanMode === 'camera' ? (
                                <div id="scan-panel-camera" role="tabpanel" aria-labelledby="scan-tab-camera" className="camera-scanner">
                                    <div style={{ margin: '0 0 1rem 0', padding: '0.75rem', background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', fontSize: '0.85rem' }}>
                                        <p style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-secondary)' }}>
                                            <Info size={16} style={{ flexShrink: 0, color: 'var(--accent-success)' }} />
                                            <span>
                                                <strong>Camera Scanning:</strong> Point your camera steadily at an InvisioVault QR code. Hold the code flat and well-lit. If the secret was encrypted with a password, you can enter it below to decrypt.
                                            </span>
                                        </p>
                                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '0.5rem', paddingTop: '0.5rem', borderTop: '1px solid var(--border-subtle)' }}>
                                            <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                                                Camera Controls:
                                            </span>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                                {torchSupported && (
                                                    <button
                                                        type="button"
                                                        onClick={toggleTorch}
                                                        className="text-button"
                                                        style={{
                                                            fontSize: '0.75rem',
                                                            padding: '2px 8px',
                                                            borderRadius: '4px',
                                                            background: torchOn ? 'rgba(255, 215, 0, 0.2)' : 'rgba(255, 255, 255, 0.08)',
                                                            color: torchOn ? '#FFD700' : 'var(--text-secondary)',
                                                            border: `1px solid ${torchOn ? '#FFD700' : 'var(--border-subtle)'}`,
                                                            cursor: 'pointer',
                                                            display: 'inline-flex',
                                                            alignItems: 'center',
                                                            gap: '4px'
                                                        }}
                                                        title="Toggle camera flashlight torch"
                                                    >
                                                        <Zap size={13} aria-hidden="true" />
                                                        <span>{torchOn ? 'Torch ON' : 'Torch OFF'}</span>
                                                    </button>
                                                )}
                                                <button
                                                    type="button"
                                                    onClick={toggleAntiMoire}
                                                    className="text-button"
                                                    style={{
                                                        fontSize: '0.75rem',
                                                        padding: '2px 8px',
                                                        borderRadius: '4px',
                                                        background: antiMoire ? 'rgba(0, 255, 136, 0.15)' : 'rgba(255, 255, 255, 0.08)',
                                                        color: antiMoire ? '#00FF88' : 'var(--text-secondary)',
                                                        border: `1px solid ${antiMoire ? '#00FF88' : 'var(--border-subtle)'}`,
                                                        cursor: 'pointer'
                                                    }}
                                                    title="Toggles optical low-pass filtering to kill screen subpixel Moiré interference on digital screens"
                                                >
                                                    {antiMoire ? (
                                                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                                            <ShieldCheck size={13} aria-hidden="true" />
                                                            <span>Anti-Moiré (Screen)</span>
                                                        </span>
                                                    ) : (
                                                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                                            <ShieldAlert size={13} aria-hidden="true" />
                                                            <span>Disabled (Paper)</span>
                                                        </span>
                                                    )}
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="camera-container">
                                        <video ref={videoRef} autoPlay playsInline muted allow="camera" className="camera-video" />
                                        <canvas ref={canvasRef} style={{ display: 'none' }} />

                                        {/* Dynamic Bounding Box Overlay */}
                                                {cameraActive && boundingBox && videoRef.current && (() => {
                                                const boxWidth = Math.hypot(
                                                    boundingBox.topRightCorner.x - boundingBox.topLeftCorner.x,
                                                    boundingBox.topRightCorner.y - boundingBox.topLeftCorner.y
                                                );
                                                // Stricter threshold: 350px ensures physical sensor resolves >= 5-8 px/module
                                                const MIN_BOX_WIDTH = 350;
                                                const isTooSmall = boxWidth < MIN_BOX_WIDTH;

                                                // Detect mobile touch devices
                                                const isMobile = typeof navigator !== 'undefined' && (
                                                    /iPhone|iPad|iPod|Android/i.test(navigator.userAgent) || 
                                                    navigator.maxTouchPoints > 0
                                                );

                                                // Stability pill label & icon
                                                let pillLabel = null
                                                let pillIcon = null
                                                let pillColor = '#00FF00'
                                                let pillBg = 'rgba(0,0,0,0.75)'
                                                if (isTooSmall) {
                                                    pillIcon = <Camera size={14} aria-hidden="true" />
                                                    pillLabel = 'Move closer'
                                                    pillColor = '#FFA500'
                                                } else if (stabilityState === 'blurry') {
                                                    pillIcon = <AlertCircle size={14} aria-hidden="true" />
                                                    pillLabel = 'Better lighting needed'
                                                    pillColor = '#FFD700'
                                                } else if (stabilityState === 'stabilizing') {
                                                    pillIcon = <RotateCcw size={14} aria-hidden="true" />
                                                    pillLabel = 'Stabilizing…'
                                                    pillColor = '#87CEEB'
                                                } else if (stabilityState === 'ready') {
                                                    pillIcon = <CheckCircle2 size={14} aria-hidden="true" />
                                                    pillLabel = 'Aligned — scanning…'
                                                    pillColor = '#00FF88'
                                                }

                                                return (
                                                    <>
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
                                                                fill={isTooSmall ? "rgba(255, 165, 0, 0.2)" : stabilityState === 'ready' ? "rgba(0, 255, 136, 0.15)" : "rgba(0, 255, 0, 0.2)"}
                                                                stroke={isTooSmall ? "#FFA500" : pillColor}
                                                                strokeWidth="4"
                                                                strokeLinejoin="round"
                                                            />
                                                        </svg>

                                                        {/* Mobile Touch-to-Focus Contextual Tip */}
                                                        {isMobile && isTooSmall && (
                                                            <div style={{
                                                                position: 'absolute',
                                                                top: '16px',
                                                                left: '50%',
                                                                transform: 'translateX(-50%)',
                                                                background: 'rgba(0, 0, 0, 0.85)',
                                                                color: '#FFD700',
                                                                padding: '8px 16px',
                                                                borderRadius: '12px',
                                                                fontSize: '0.78rem',
                                                                fontWeight: '500',
                                                                textAlign: 'center',
                                                                maxWidth: '90%',
                                                                pointerEvents: 'none',
                                                                zIndex: 12,
                                                                border: '1px solid rgba(255, 215, 0, 0.4)',
                                                                boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
                                                            }}>
                                                                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                                                                    <Info size={14} aria-hidden="true" style={{ flexShrink: 0, color: '#FFD700' }} />
                                                                    <span>Tip: If blurry, tap the screen to focus, or move back slightly and let the QR fill the frame.</span>
                                                                </span>
                                                            </div>
                                                        )}

                                                        {pillLabel && (
                                                            <div style={{
                                                                position: 'absolute',
                                                                bottom: '16px',
                                                                left: '50%',
                                                                transform: 'translateX(-50%)',
                                                                background: pillBg,
                                                                color: pillColor,
                                                                padding: '6px 14px',
                                                                borderRadius: '20px',
                                                                fontSize: '0.82rem',
                                                                fontWeight: '500',
                                                                pointerEvents: 'none',
                                                                zIndex: 12,
                                                                border: `1px solid ${pillColor}`,
                                                                whiteSpace: 'nowrap',
                                                                display: 'inline-flex',
                                                                alignItems: 'center',
                                                                gap: '6px',
                                                            }}>
                                                                {pillIcon}
                                                                <span>{pillLabel}</span>
                                                            </div>
                                                        )}
                                                    </>
                                                );
                                            })()}

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
                                                <span>QR detected — Checking for hidden message…</span>
                                            </p>
                                        </div>
                                    )}

                                    {extractError && !scanError && !cameraError && (
                                        <div className="error-message" role="alert" style={{ display: 'flex', flexDirection: 'column', gap: '8px', alignItems: 'flex-start' }}>
                                            <span>{extractError}</span>
                                            {!pendingScan && (
                                                <button
                                                    type="button"
                                                    className="mode-btn"
                                                    style={{ fontSize: '0.8rem', padding: '5px 10px', display: 'inline-flex', alignItems: 'center', gap: '5px' }}
                                                    onClick={() => {
                                                        setExtractError('')
                                                        if (clearCooldown) clearCooldown()
                                                        resetScanner()
                                                    }}
                                                >
                                                    <RotateCcw size={13} />
                                                    <span>Retry Scan</span>
                                                </button>
                                            )}
                                        </div>
                                    )}

                                    {/* Password input for camera mode */}
                                    <div className="form-group" style={{ marginTop: '1rem' }}>
                                        <label htmlFor="camera-password">Password (if encrypted)</label>
                                        <div className="password-input-wrapper">
                                            <input
                                                id="camera-password"
                                                type={showExtractPassword ? "text" : "password"}
                                                placeholder={pendingScan ? "Enter password to unlock hidden secret" : "Enter password (if encrypted)"}
                                                value={extractPassword}
                                                onChange={(e) => {
                                                    setExtractPassword(e.target.value)
                                                    setExtractError('')
                                                }}
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
                                        {pendingScan && (
                                            <div style={{ marginTop: '0.75rem', display: 'flex', gap: '8px' }}>
                                                <button
                                                    type="button"
                                                    className="submit-button"
                                                    style={{ flex: 1, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '6px', margin: 0 }}
                                                    disabled={extractLoading || !extractPassword.trim()}
                                                    onClick={handleUnlockPendingScan}
                                                >
                                                    <Lock size={16} />
                                                    <span>Unlock Secret</span>
                                                </button>
                                                <button
                                                    type="button"
                                                    className="mode-btn"
                                                    style={{ padding: '0 12px' }}
                                                    onClick={() => {
                                                        setPendingScan(null)
                                                        setExtractError('')
                                                        if (clearCooldown) clearCooldown()
                                                        resetScanner()
                                                    }}
                                                >
                                                    <RotateCcw size={14} />
                                                    <span>Rescan</span>
                                                </button>
                                            </div>
                                        )}
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
                                <CheckCircle2 size={48} strokeWidth={1.75} color="var(--accent-success)" />
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
                                            <span>No hidden secret message detected in this scan.</span>
                                        </p>
                                    </div>
                                    <div style={{ marginTop: 'var(--space-2)', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                                        <p style={{ margin: '4px 0' }}>
                                            <strong>Did you create this QR code with InvisioVault?</strong>
                                        </p>
                                        <ul style={{ margin: '4px 0 8px 1.25rem', padding: 0, lineHeight: 1.5 }}>
                                            <li>
                                                If you scanned a digital screen, glare, moiré interference, or reflections can degrade subtle pixel luminance. Try reducing glare, holding steady, or use <strong>Upload Image</strong> with the original saved PNG.
                                            </li>
                                            <li>
                                                If the QR code was <strong>password-protected</strong>, make sure the password was entered before scanning/extracting.
                                            </li>
                                        </ul>
                                        <button
                                            type="button"
                                            className="mode-btn"
                                            style={{ fontSize: '0.8rem', padding: '6px 12px', marginTop: '6px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                                            onClick={() => { setScanMode('upload'); resetExtract(); }}
                                        >
                                            <Upload size={14} />
                                            <span>Switch to Upload Image</span>
                                        </button>
                                    </div>
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
