/**
 * QR Scanner Hook - Client-side detection with jsQR
 * Provides real-time bounding box feedback and reduces server load.
 */
import { useEffect, useRef, useState, useCallback } from 'react'
import jsQR from 'jsqr'

export function useQRScanner(isActive, onQRDetected, onError) {
    const videoRef = useRef(null)
    const canvasRef = useRef(null)
    const [isScanning, setIsScanning] = useState(false)
    const [error, setError] = useState(null)
    const [boundingBox, setBoundingBox] = useState(null)

    const streamRef = useRef(null)
    const animationFrameRef = useRef(null)

    // throttle scanning to avoid CPU spike
    const lastScanTimeRef = useRef(0)
    const SCAN_INTERVAL = 100 // scan every 100ms

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
            setBoundingBox(null)

            if (!window.isSecureContext) {
                throw new Error('Camera requires HTTPS or localhost.')
            }

            if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
                throw new Error('Camera API not supported in this browser')
            }

            const cameraConfigs = [
                { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } },
                { facingMode: 'environment' },
                { facingMode: 'user' }
            ]

            let stream = null
            let lastError = null

            for (const config of cameraConfigs) {
                try {
                    stream = await navigator.mediaDevices.getUserMedia({ video: config })
                    break
                } catch (err) {
                    lastError = err
                }
            }

            if (!stream) {
                throw lastError || new Error('Failed to get camera stream')
            }

            console.log('[QR Scanner] Camera access granted')
            streamRef.current = stream

            if (videoRef.current) {
                videoRef.current.srcObject = stream
                // Wait for video to be ready
                videoRef.current.onloadedmetadata = () => {
                    videoRef.current.play().then(() => {
                        setIsScanning(true)
                        scanFrame()
                    }).catch(e => {
                        console.error("Play error:", e)
                        setError("Failed to start video stream")
                    })
                }
            }
        } catch (err) {
            console.error('[QR Scanner] Camera access error:', err)
            let errorMsg = err.message || 'Camera access denied.'
            if (err.name === 'NotAllowedError') errorMsg = 'Camera permission denied.'
            if (err.name === 'NotFoundError') errorMsg = 'No camera found.'
            if (err.name === 'NotReadableError') errorMsg = 'Camera is in use by another app.'

            setError(errorMsg)
            setIsScanning(false)
            if (onErrorRef.current) onErrorRef.current(err)
        }
    }

    const scanFrame = () => {
        const video = videoRef.current
        const canvas = canvasRef.current

        if (!video || !canvas || video.readyState !== video.HAVE_ENOUGH_DATA) {
            animationFrameRef.current = requestAnimationFrame(scanFrame)
            return
        }

        const now = Date.now()
        if (now - lastScanTimeRef.current < SCAN_INTERVAL) {
            animationFrameRef.current = requestAnimationFrame(scanFrame)
            return
        }
        lastScanTimeRef.current = now

        try {
            const ctx = canvas.getContext('2d', { willReadFrequently: true })

            if (canvas.width !== video.videoWidth || canvas.height !== video.videoHeight) {
                canvas.width = video.videoWidth
                canvas.height = video.videoHeight
            }

            ctx.drawImage(video, 0, 0, canvas.width, canvas.height)
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height)

            const code = jsQR(imageData.data, imageData.width, imageData.height, {
                inversionAttempts: "dontInvert",
            })

            if (code) {
                console.log('[QR Scanner] QR Code detected locally:', code.data)
                setBoundingBox(code.location)

                if (onQRDetectedRef.current) {
                    // Create a blob with the raw data attached to maintain compatibility
                    // The component treats this blob as 'scanned-qr.png'
                    canvas.toBlob((blob) => {
                        if (blob) {
                            blob.rawQrData = code.data
                            onQRDetectedRef.current(blob)
                        }
                    })
                }
            } else {
                setBoundingBox(null)
            }

        } catch (err) {
            console.error('[QR Scanner] Frame scan error:', err)
        }

        animationFrameRef.current = requestAnimationFrame(scanFrame)
    }

    const stopScanning = useCallback(() => {
        if (animationFrameRef.current) {
            cancelAnimationFrame(animationFrameRef.current)
            animationFrameRef.current = null
        }

        if (streamRef.current) {
            streamRef.current.getTracks().forEach(track => track.stop())
            streamRef.current = null
        }

        if (videoRef.current) {
            videoRef.current.srcObject = null
        }

        setIsScanning(false)
        setBoundingBox(null)
    }, [])

    const reset = () => {
        setError(null)
        setBoundingBox(null)
        if (isActive) startScanning()
    }

    return {
        videoRef,
        canvasRef,
        error,
        isScanning,
        boundingBox,
        reset,
        stopScanning
    }
}
