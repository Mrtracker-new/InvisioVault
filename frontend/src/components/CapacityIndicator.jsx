import { useState, useEffect } from 'react'
import axios from 'axios'
import './CapacityIndicator.css'
import API_URL from '../config/api'

function CapacityIndicator({ carrierFile, hiddenFile, hiddenText, mode = 'stego', password }) {
    const [capacity, setCapacity] = useState(null)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState('')

    // Calculate file size with overhead
    const calculateUsedBytes = (file, text, hasPassword) => {
        // Fixed overhead from steganography.py structure:
        // password_flag(1) + metadata_length(2) + data_length(4) = 7 bytes
        let overhead = 7

        // Add salt overhead if password protected
        if (hasPassword) {
            overhead += 16 // salt bytes
        }

        // Estimate metadata size (filename|mime_type)
        let metadataSize = 0
        if (file) {
            const mimeType = file.type || 'application/octet-stream'
            metadataSize = (file.name + '|' + mimeType).length
        } else if (text) {
            metadataSize = ('hidden_text.txt|text/plain').length
        }

        // Get actual file/text size
        let dataSize = 0
        if (file) {
            dataSize = file.size
        } else if (text) {
            dataSize = new Blob([text]).size
        }

        // Compression typically reduces size by 20-50% for text, less for binary
        // We'll estimate conservatively (assume 30% compression for safety)
        const estimatedCompressedSize = Math.ceil(dataSize * 0.7)

        // Total size = overhead + metadata + compressed data
        return overhead + metadataSize + estimatedCompressedSize
    }

    // Format bytes to human-readable string
    const formatBytes = (bytes) => {
        if (bytes === 0) return '0 Bytes'
        if (bytes < 1024) return `${bytes} Bytes`
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    }

    // Get status based on percentage
    const getStatus = (percentage) => {
        // Determine if we're hiding text or a file
        const contentType = hiddenText ? 'Text' : 'File'

        if (percentage > 100) {
            return {
                level: 'error',
                icon: '❌',
                message: `${contentType} is too large for this image`
            }
        } else if (percentage > 90) {
            return {
                level: 'warning',
                icon: '⚠️',
                message: `${contentType} will barely fit - consider using a larger image`
            }
        } else if (percentage > 70) {
            return {
                level: 'caution',
                icon: '⚡',
                message: `${contentType} will fit, but capacity is high`
            }
        } else {
            return {
                level: 'success',
                icon: '✅',
                message: `${contentType} will fit comfortably`
            }
        }
    }

    useEffect(() => {
        const calculateCapacity = async () => {
            if (!carrierFile) {
                setCapacity(null)
                return
            }

            setLoading(true)
            setError('')

            try {
                // Get total capacity from backend
                const formData = new FormData()
                formData.append('image', carrierFile)

                const response = await axios.post(`${API_URL}/api/calculate-capacity`, formData, {
                    headers: {
                        'Content-Type': 'multipart/form-data'
                    }
                })

                const totalBytes = response.data.totalCapacityBytes

                // Calculate used bytes
                const usedBytes = calculateUsedBytes(hiddenFile, hiddenText, !!password)
                const percentage = Math.round((usedBytes / totalBytes) * 100)

                setCapacity({
                    totalBytes,
                    usedBytes,
                    percentage,
                    totalFormatted: formatBytes(totalBytes),
                    usedFormatted: formatBytes(usedBytes)
                })
            } catch (err) {
                setError(err.response?.data?.error || 'Failed to calculate capacity')
            } finally {
                setLoading(false)
            }
        }

        // Debounce the capacity calculation to prevent excessive API calls
        const timeoutId = setTimeout(() => {
            calculateCapacity()
        }, 500) // 500ms delay

        return () => clearTimeout(timeoutId)
    }, [carrierFile, hiddenFile, hiddenText, password, mode])

    if (!carrierFile || (!hiddenFile && !hiddenText)) {
        return null
    }

    if (loading) {
        return (
            <div className="capacity-indicator loading">
                <div className="capacity-spinner"></div>
                <p>Calculating capacity...</p>
            </div>
        )
    }

    if (error) {
        return (
            <div className="capacity-indicator error">
                <p>⚠️ {error}</p>
            </div>
        )
    }

    if (!capacity) {
        return null
    }

    const status = getStatus(capacity.percentage)
    const progressWidth = Math.min(capacity.percentage, 100)

    return (
        <div className={`capacity-indicator ${status.level}`}>
            <div className="capacity-header">
                <h4>📊 Capacity Analysis</h4>
            </div>

            <div className="capacity-stats">
                <div className="stat">
                    <span className="stat-label">Image Capacity:</span>
                    <span className="stat-value">{capacity.totalFormatted}</span>
                </div>
                <div className="stat">
                    <span className="stat-label">{hiddenText ? 'Text Size' : 'File Size'} (estimated):</span>
                    <span className="stat-value">{capacity.usedFormatted}</span>
                </div>
            </div>

            <div className="progress-container">
                <div className="progress-bar">
                    <div
                        className={`progress-fill ${status.level}`}
                        style={{ width: `${progressWidth}%` }}
                    >
                        <div className="progress-shine"></div>
                    </div>
                </div>
                <div className="progress-label">
                    {capacity.percentage}% capacity used
                </div>
            </div>

            <div className={`status-message ${status.level}`}>
                <span className="status-icon">{status.icon}</span>
                <span className="status-text">{status.message}</span>
            </div>

            {mode === 'stego' && (
                <div className="capacity-note">
                    <small>
                        ℹ️ Capacity based on LSB steganography (3 bits per pixel).
                        {password && ' Encryption adds ~16 bytes overhead.'}
                    </small>
                </div>
            )}
        </div>
    )
}

export default CapacityIndicator
