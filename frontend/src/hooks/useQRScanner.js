/**
 * QR Scanner Hook - sends camera frames to backend for detection
 * More robust than client-side jsQR
 */
import { useEffect, useRef, useState, useCallback } from 'react'
import API_URL from '../config/api'

export function useQRScanner(isActive, onQRDetected, onError) {
    const videoRef = useRef(null)
    const canvasRef = useRef(null)
    const [isScanning, setIsScanning] = useState(false)
    const [error, setError] = useState(null)
    const streamRef = useRef(null)
    const scanIntervalRef = useRef(null)
    const isProcessingRef = useRef(false) // Prevent concurrent scans
    const failureCountRef = useRef(0) // Track consecutive failures for adaptive interval
    const currentIntervalRef = useRef(500) // Current scan interval in ms

    // Use callback refs to ensure we always have latest values
    const onQRDetectedRef = useRef(onQRDetected)
    const onErrorRef = useRef(onError)

    useEffect(() => {
        onQRDetectedRef.current = onQRDetected
        onErrorRef.current = onError
    }, [onQRDetected, onError])

    useEffect(() => {
        console.log('[QR Scanner] Hook activated:', isActive)

        if (!isActive) {
            stopScanning()
            return
        }

        startScanning()

        return () => {
            console.log('[QR Scanner] Cleaning up...')
            stopScanning()
        }
    }, [isActive])

    const startScanning = async () => {
        try {
            console.log('[QR Scanner] Starting camera access...')
            setError(null)

            // Check if running on HTTPS or localhost (required for camera API)
            const isSecureContext = window.isSecureContext
            if (!isSecureContext) {
                const errorMsg = 'Camera requires HTTPS or localhost. Please use a secure connection.'
                console.error('[QR Scanner]', errorMsg)
                setError(errorMsg)
                if (onErrorRef.current) onErrorRef.current(new Error(errorMsg))
                return
            }

            // Check if mediaDevices API is available
            if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
                const errorMsg = 'Camera API not supported in this browser'
                console.error('[QR Scanner]', errorMsg)
                setError(errorMsg)
                if (onErrorRef.current) onErrorRef.current(new Error(errorMsg))
                return
            }

            // Request camera access with progressive fallback
            console.log('[QR Scanner] Requesting camera permissions...')

            // Progressive fallback configurations
            const cameraConfigs = [
                // Try ideal settings first
                { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } },
                // Fallback to lower resolution
                { facingMode: 'environment', width: { ideal: 640 }, height: { ideal: 480 } },
                // Try rear camera with any resolution
                { facingMode: 'environment' },
                // Last resort: any camera, any resolution
                { facingMode: 'user' },
                // Absolute fallback
                true
            ]

            let stream = null
            let lastError = null

            for (let i = 0; i < cameraConfigs.length; i++) {
                try {
                    const config = cameraConfigs[i]
                    console.log(`[QR Scanner] Trying camera config ${i + 1}/${cameraConfigs.length}...`)
                    stream = await navigator.mediaDevices.getUserMedia({
                        video: config
                    })

                    // Log actual camera settings obtained
                    if (stream && stream.getVideoTracks().length > 0) {
                        const track = stream.getVideoTracks()[0]
                        const settings = track.getSettings()
                        console.log('[QR Scanner] Camera settings:', {
                            width: settings.width,
                            height: settings.height,
                            facingMode: settings.facingMode,
                            deviceId: settings.deviceId
                        })
                    }

                    break // Success!
                } catch (err) {
                    lastError = err
                    console.warn(`[QR Scanner] Config ${i + 1} failed:`, err.message)
                    if (i === cameraConfigs.length - 1) {
                        throw lastError // Re-throw if all configs failed
                    }
                }
            }

            if (!stream) {
                throw lastError || new Error('Failed to get camera stream')
            }

            console.log('[QR Scanner] Camera access granted')
            streamRef.current = stream

            if (videoRef.current) {
                videoRef.current.srcObject = stream
                await videoRef.current.play()
                setIsScanning(true)
                console.log('[QR Scanner] Video stream started')

                // Start periodic scanning with adaptive interval
                console.log('[QR Scanner] Starting periodic frame scanning...')
                const startAdaptiveScanning = () => {
                    if (scanIntervalRef.current) {
                        clearInterval(scanIntervalRef.current)
                    }
                    scanIntervalRef.current = setInterval(() => {
                        captureAndScan()
                    }, currentIntervalRef.current)
                    console.log(`[QR Scanner] Scan interval set to ${currentIntervalRef.current}ms`)
                }
                startAdaptiveScanning()
            }
        } catch (err) {
            console.error('[QR Scanner] Camera access error:', err)
            let errorMsg = 'Camera access denied. Please allow camera permissions or use file upload.'

            if (err.name === 'NotAllowedError') {
                errorMsg = 'Camera permission denied. Please allow camera access in your browser settings.'
            } else if (err.name === 'NotFoundError') {
                errorMsg = 'No camera found on this device. Please use file upload instead.'
            } else if (err.name === 'NotReadableError') {
                errorMsg = 'Camera is already in use by another application.'
            }

            setError(errorMsg)
            setIsScanning(false)
            if (onErrorRef.current) onErrorRef.current(err)
        }
    }

    const captureAndScan = async () => {
        // Prevent concurrent scans
        if (isProcessingRef.current) {
            console.log('[QR Scanner] Skipping frame - previous scan still processing')
            return
        }

        const video = videoRef.current
        const canvas = canvasRef.current

        if (!video || !canvas || !video.videoWidth) {
            console.log('[QR Scanner] Video not ready yet')
            return
        }

        isProcessingRef.current = true

        try {
            // Create ORIGINAL canvas for extraction (preserves color for steganography)
            const originalCanvas = document.createElement('canvas')
            const originalContext = originalCanvas.getContext('2d')
            originalCanvas.width = video.videoWidth
            originalCanvas.height = video.videoHeight
            originalContext.drawImage(video, 0, 0, originalCanvas.width, originalCanvas.height)

            // Create ENHANCED canvas for QR detection (2x upscaling + grayscale + contrast)
            // Capture current frame with 2x upscaling for better QR detection
            const context = canvas.getContext('2d')
            const scaleFactor = 2 // 2x upscaling
            canvas.width = video.videoWidth * scaleFactor
            canvas.height = video.videoHeight * scaleFactor

            // Draw with high-quality scaling
            context.imageSmoothingEnabled = true
            context.imageSmoothingQuality = 'high'
            context.drawImage(video, 0, 0, canvas.width, canvas.height)

            // Apply grayscale and contrast enhancement
            const imageData = context.getImageData(0, 0, canvas.width, canvas.height)
            const data = imageData.data

            for (let i = 0; i < data.length; i += 4) {
                // Convert to grayscale
                const gray = 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2]

                // Apply contrast enhancement (+50%)
                const contrast = 1.5
                const enhanced = ((gray - 128) * contrast) + 128
                const final = Math.max(0, Math.min(255, enhanced))

                data[i] = final     // R
                data[i + 1] = final // G
                data[i + 2] = final // B
                // Alpha channel (i+3) remains unchanged
            }

            context.putImageData(imageData, 0, 0)

            console.log('[QR Scanner] Frame captured and enhanced, sending to backend...')

            // Convert to blob with maximum quality
            canvas.toBlob(async (blob) => {
                if (!blob) {
                    console.warn('[QR Scanner] Failed to create blob from canvas')
                    isProcessingRef.current = false
                    increaseInterval() // Increase interval on failure
                    return
                }

                try {
                    const formData = new FormData()
                    formData.append('image', blob, 'camera-frame.png')

                    // Quick check endpoint - just decode QR, don't extract secrets yet
                    const response = await fetch(`${API_URL}/api/qr/detect`, {
                        method: 'POST',
                        body: formData
                    })

                    console.log('[QR Scanner] Detection response status:', response.status)

                    if (response.ok) {
                        const data = await response.json()
                        console.log('[QR Scanner] Detection result:', data)

                        if (data.detected) {
                            // QR found! Convert ORIGINAL frame to blob for extraction
                            console.log('[QR Scanner] ✓ QR code detected! Preparing original frame for extraction...')

                            originalCanvas.toBlob((originalBlob) => {
                                if (originalBlob && onQRDetectedRef.current) {
                                    console.log('[QR Scanner] Calling onQRDetected callback with ORIGINAL color frame')
                                    resetInterval() // Reset for next scan
                                    stopScanning()
                                    onQRDetectedRef.current(originalBlob) // Pass ORIGINAL blob for extraction
                                } else {
                                    console.error('[QR Scanner] Failed to create original blob')
                                    increaseInterval()
                                }
                            }, 'image/png', 1.0)

                        } else {
                            // No QR detected, increase interval
                            increaseInterval()
                        }
                    } else {
                        console.error('[QR Scanner] Detection endpoint error:', response.status)
                        increaseInterval() // Back off on errors
                    }
                } catch (err) {
                    // Silently fail - continues scanning on next interval
                    console.log('[QR Scanner] Scan attempt failed:', err.message)
                    increaseInterval() // Back off on errors
                } finally {
                    isProcessingRef.current = false
                }
            }, 'image/png', 1.0)
        } catch (err) {
            console.error('[QR Scanner] Frame capture error:', err)
            isProcessingRef.current = false
        }
    }

    // Adaptive interval management
    const increaseInterval = () => {
        failureCountRef.current++

        // Exponential backoff: 500ms → 1000ms → 2000ms (max)
        if (failureCountRef.current >= 3 && currentIntervalRef.current < 2000) {
            const newInterval = Math.min(currentIntervalRef.current * 2, 2000)
            if (newInterval !== currentIntervalRef.current) {
                currentIntervalRef.current = newInterval
                console.log(`[QR Scanner] Increased scan interval to ${currentIntervalRef.current}ms`)

                // Restart interval with new timing
                if (scanIntervalRef.current && isScanning) {
                    clearInterval(scanIntervalRef.current)
                    scanIntervalRef.current = setInterval(() => {
                        captureAndScan()
                    }, currentIntervalRef.current)
                }
            }
            failureCountRef.current = 0 // Reset counter after adjustment
        }
    }

    const resetInterval = () => {
        failureCountRef.current = 0
        if (currentIntervalRef.current !== 500) {
            currentIntervalRef.current = 500
            console.log('[QR Scanner] Reset scan interval to 500ms')
        }
    }

    const stopScanning = useCallback(() => {
        console.log('[QR Scanner] Stopping scanner...')

        // Stop scan interval
        if (scanIntervalRef.current) {
            clearInterval(scanIntervalRef.current)
            scanIntervalRef.current = null
            console.log('[QR Scanner] Scan interval cleared')
        }

        // Stop video stream
        if (streamRef.current) {
            streamRef.current.getTracks().forEach(track => {
                track.stop()
                console.log('[QR Scanner] Stopped track:', track.kind)
            })
            streamRef.current = null
        }

        // Clear video element
        if (videoRef.current) {
            videoRef.current.srcObject = null
        }

        isProcessingRef.current = false
        setIsScanning(false)
        resetInterval() // Reset interval on stop
        console.log('[QR Scanner] Scanner stopped')
    }, [])

    const reset = () => {
        console.log('[QR Scanner] Resetting scanner...')
        setError(null)
        if (isActive) {
            startScanning()
        }
    }

    return {
        videoRef,
        canvasRef,
        error,
        isScanning,
        reset,
        stopScanning
    }
}
