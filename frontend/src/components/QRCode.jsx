import { useState, useEffect } from 'react'
import axios from 'axios'
import './QRCode.css'
import API_URL from '../config/api'
import { useQRScanner } from '../hooks/useQRScanner'

function QRCode() {
    const [activeTab, setActiveTab] = useState('generate') // 'generate' or 'extract'
    const [scanMode, setScanMode] = useState('camera') // 'camera' or 'upload'

    // Generation state
    const [publicData, setPublicData] = useState('')
    const [secretText, setSecretText] = useState('')
    const [password, setPassword] = useState('')
    const [showPassword, setShowPassword] = useState(false)
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

    // Camera scanner with callbacks
    const isScanning = activeTab === 'extract' && scanMode === 'camera'

    const handleQRDetected = async (blob) => {
        // QR detected from camera - now extract hidden data
        console.log('[QRCode Component] QR detected from camera, extracting data...')
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
        setExtractError('Camera error: ' + err.message)
    }

    const { videoRef, canvasRef, error: scanError, isScanning: cameraActive, reset: resetScanner } = useQRScanner(
        isScanning,
        handleQRDetected,
        handleScanError
    )

    // Remove old useEffect that was based on qrData
    // The hook now calls handleQRDetected directly when QR is found

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
        window.open(`${API_URL}/api/qr/download/${downloadId}`, '_blank')
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
        resetScanner()
        if (document.getElementById('qr-upload')) {
            document.getElementById('qr-upload').value = ''
        }
    }

    const copyToClipboard = (text, type) => {
        navigator.clipboard.writeText(text)
        alert(`${type} copied to clipboard!`)
    }

    return (
        <div className="qr-code">
            <h2>📱 QR Code Steganography</h2>
            <p className="description">
                Generate customized QR codes with hidden messages, or scan to reveal secrets
            </p>

            <div className="tab-container-qr">
                <button
                    className={`tab-qr ${activeTab === 'generate' ? 'active' : ''}`}
                    onClick={() => { setActiveTab('generate'); setError(''); setExtractError(''); }}
                >
                    ✨ Generate
                </button>
                <button
                    className={`tab-qr ${activeTab === 'extract' ? 'active' : ''}`}
                    onClick={() => { setActiveTab('extract'); setError(''); setExtractError(''); }}
                >
                    🔍 Scan & Extract
                </button>
            </div>

            {activeTab === 'generate' ? (
                <div className="qr-generate">
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
                                <h3>🎨 Customization</h3>

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
                                    <label htmlFor="scale">Size: {scale}</label>
                                    <input
                                        id="scale"
                                        type="range"
                                        min="5"
                                        max="20"
                                        value={scale}
                                        onChange={(e) => setScale(parseInt(e.target.value))}
                                    />
                                    <small>Adjust the QR code size (larger = higher capacity)</small>
                                </div>

                                <div className="form-group">
                                    <label htmlFor="logo-input">Logo (Optional)</label>
                                    <input
                                        id="logo-input"
                                        type="file"
                                        accept="image/*"
                                        onChange={(e) => setLogo(e.target.files[0])}
                                    />
                                    {logo && <p className="file-name">Logo: {logo.name}</p>}
                                    <small>Add a logo in the center of your QR code</small>
                                </div>
                            </div>

                            <div className="form-group">
                                <label htmlFor="password-input">Password (Optional) 🔒</label>
                                <div className="password-input-wrapper">
                                    <input
                                        id="password-input"
                                        type={showPassword ? "text" : "password"}
                                        placeholder="Enter password to encrypt the secret"
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
                                            {showPassword ? '👁️' : '🙈'}
                                        </button>
                                    )}
                                </div>
                                {password && <p className="file-name">🔐 Secret will be password-protected</p>}
                            </div>

                            {error && <div className="error-message">{error}</div>}

                            <button type="submit" disabled={loading} className="submit-button">
                                {loading ? 'Generating...' : '✨ Generate QR Code'}
                            </button>
                        </form>
                    ) : (
                        <div className="success-card">
                            <div className="success-icon">✅</div>
                            <h3>QR Code Generated Successfully!</h3>
                            {qrPreview && (
                                <div className="qr-preview">
                                    <img src={qrPreview} alt="Generated QR Code" />
                                    <p className="preview-hint">
                                        📱 Scan with phone → Shows: {publicData}<br />
                                        🔍 Scan with InvisioVault → Also reveals secret message
                                    </p>
                                </div>
                            )}
                            <button onClick={handleDownload} className="download-button">
                                📥 Download QR Code
                            </button>
                            <button onClick={resetGenerate} className="new-button">
                                Create Another QR Code
                            </button>
                        </div>
                    )}
                </div>
            ) : (
                <div className="qr-extract">
                    {!extractedData ? (
                        <div>
                            {/* Scan Mode Toggle */}
                            <div className="scan-mode-toggle">
                                <button
                                    className={`mode-btn ${scanMode === 'camera' ? 'active' : ''}`}
                                    onClick={() => setScanMode('camera')}
                                >
                                    📷 Camera Scan
                                </button>
                                <button
                                    className={`mode-btn ${scanMode === 'upload' ? 'active' : ''}`}
                                    onClick={() => setScanMode('upload')}
                                >
                                    📤 Upload Image
                                </button>
                            </div>

                            {scanMode === 'camera' ? (
                                <div className="camera-scanner">
                                    <div className="camera-container">
                                        <video ref={videoRef} autoPlay playsInline className="camera-video" />
                                        <canvas ref={canvasRef} style={{ display: 'none' }} />

                                        {!cameraActive && !scanError && (
                                            <div className="camera-placeholder">
                                                <p>📷 Starting camera...</p>
                                            </div>
                                        )}

                                        {cameraActive && (
                                            <div className="scanning-overlay">
                                                <div className="scan-frame"></div>
                                                <p className="scan-hint">📱 Point your camera at a QR code</p>
                                            </div>
                                        )}
                                    </div>

                                    {scanError && (
                                        <div className="error-message">
                                            {scanError}
                                            <p style={{ marginTop: '8px', fontSize: '0.875rem' }}>
                                                Switch to "Upload Image" mode instead.
                                            </p>
                                        </div>
                                    )}

                                    {extractLoading && (
                                        <div className="scanning-status">
                                            <p>🔍 Extracting hidden data...</p>
                                        </div>
                                    )}

                                    {extractError && !scanError && (
                                        <div className="error-message">{extractError}</div>
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
                                                    aria-label="Toggle password visibility"
                                                >
                                                    {showExtractPassword ? '👁️' : '🙈'}
                                                </button>
                                            )}
                                        </div>
                                        <small>Enter password before scanning if your QR is encrypted</small>
                                    </div>
                                </div>
                            ) : (
                                <form onSubmit={handleExtract}>
                                    <div className="form-group">
                                        <label htmlFor="qr-upload">Upload QR Code Image</label>
                                        <input
                                            id="qr-upload"
                                            type="file"
                                            accept="image/*"
                                            onChange={(e) => setUploadedQR(e.target.files[0])}
                                            required
                                        />
                                        {uploadedQR && <p className="file-name">Selected: {uploadedQR.name}</p>}
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
                                                    aria-label="Toggle password visibility"
                                                >
                                                    {showExtractPassword ? '👁️' : '🙈'}
                                                </button>
                                            )}
                                        </div>
                                    </div>

                                    {extractError && <div className="error-message">{extractError}</div>}

                                    <button type="submit" disabled={extractLoading} className="submit-button">
                                        {extractLoading ? 'Scanning...' : '🔍 Scan & Extract'}
                                    </button>
                                </form>
                            )}
                        </div>
                    ) : (
                        <div className="extracted-data">
                            <div className="success-icon">🎉</div>
                            <h3>Data Extracted Successfully!</h3>

                            <div className="data-section">
                                <h4>📱 Public Data (Visible):</h4>
                                <div className="data-box">
                                    <p>{extractedData.publicData}</p>
                                    <button
                                        className="copy-btn"
                                        onClick={() => copyToClipboard(extractedData.publicData, 'Public data')}
                                    >
                                        📋 Copy
                                    </button>
                                </div>
                            </div>

                            {extractedData.secretData ? (
                                <div className="data-section">
                                    <h4>🔐 Hidden Secret Message:</h4>
                                    <div className="data-box secret">
                                        <p>{extractedData.secretData}</p>
                                        <button
                                            className="copy-btn"
                                            onClick={() => copyToClipboard(extractedData.secretData, 'Secret data')}
                                        >
                                            📋 Copy
                                        </button>
                                    </div>
                                </div>
                            ) : (
                                <div className="data-section">
                                    <h4>🔐 Hidden Secret Message:</h4>
                                    <div className="data-box" style={{ background: 'var(--bg-elevated)', borderStyle: 'dashed' }}>
                                        <p style={{ color: 'var(--text-tertiary)', fontStyle: 'italic' }}>
                                            ℹ️ No hidden data found. This appears to be a regular QR code without steganographic content.
                                        </p>
                                    </div>
                                    <small style={{ display: 'block', marginTop: 'var(--space-2)', color: 'var(--text-tertiary)' }}>
                                        Only QR codes generated with InvisioVault contain hidden messages.
                                    </small>
                                </div>
                            )}

                            <button onClick={resetExtract} className="new-button">
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
