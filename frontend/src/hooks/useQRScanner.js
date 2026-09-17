/**
 * QR Scanner Hook - Client-side detection with jsQR
 * Provides real-time bounding box feedback and reduces server load.
 */
import { useEffect, useRef, useState, useCallback } from 'react'
import jsQR from 'jsqr'

// Only emit verbose logs in development builds (Vite strips import.meta.env.DEV in production)
const DEV = import.meta.env.DEV

export function useQRScanner(isActive, onQRDetected, onError, isPaused = false) {
    const videoRef = useRef(null)
    const canvasRef = useRef(null)
    const [isScanning, setIsScanning] = useState(false)
    const [error, setError] = useState(null)
    const [boundingBox, setBoundingBox] = useState(null)

    const isPausedRef = useRef(isPaused)
    useEffect(() => {
        isPausedRef.current = isPaused
    }, [isPaused])

    const streamRef = useRef(null)
    const animationFrameRef = useRef(null)
    const isProcessingRef = useRef(false)

    // throttle scanning to avoid CPU spike
    const lastScanTimeRef = useRef(0)
    const SCAN_INTERVAL = 100 // scan every 100ms

    // Deduplication & cooldown to prevent flooding server
    const lastScannedDataRef = useRef(null)
    const lastScannedTimeRef = useRef(0)
    const SCAN_COOLDOWN_MS = 3000 // 3 seconds cooldown before re-scanning the exact same QR code

    // Use callback refs to ensure we always have latest values
    const onQRDetectedRef = useRef(onQRDetected)
    const onErrorRef = useRef(onError)

    useEffect(() => {
        onQRDetectedRef.current = onQRDetected
        onErrorRef.current = onError
    }, [onQRDetected, onError])

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

    const scanFrame = useCallback(() => {
        if (!streamRef.current) {
            return
        }

        const video = videoRef.current
        const canvas = canvasRef.current

        if (!video || !canvas || video.readyState !== video.HAVE_ENOUGH_DATA) {
            if (streamRef.current) {
                animationFrameRef.current = requestAnimationFrame(scanFrame)
            }
            return
        }

        if (isPausedRef.current) {
            if (streamRef.current) {
                animationFrameRef.current = requestAnimationFrame(scanFrame)
            }
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

            if (code && !isProcessingRef.current && !isPausedRef.current) {
                const now = Date.now()
                const isSameCode = lastScannedDataRef.current === code.data
                const isCoolingDown = now - lastScannedTimeRef.current < SCAN_COOLDOWN_MS

                setBoundingBox(code.location)

                if ((!isSameCode || !isCoolingDown) && onQRDetectedRef.current) {
                    const videoDims = {
                        videoWidth: video.videoWidth,
                        videoHeight: video.videoHeight,
                        clientWidth: video.clientWidth,
                        clientHeight: video.clientHeight,
                    }
                    const canvasDims = {
                        canvasWidth: canvas.width,
                        canvasHeight: canvas.height,
                    }
                    const dpr = window.devicePixelRatio || 1

                    if (DEV) {
                        console.log('[QR Scanner] QR Code detected locally:', code.data)
                        console.log('[QR Scanner] Camera & Canvas Metrics:', {
                            video: videoDims,
                            canvas: canvasDims,
                            devicePixelRatio: dpr,
                            version: code.version,
                            location: code.location
                        })
                    }

                    lastScannedDataRef.current = code.data
                    lastScannedTimeRef.current = now
                    isProcessingRef.current = true

                    // ── Step 1: Snapshot the current canvas frame ────────────────────────────
                    // Capture synchronously so subsequent rAF ticks don't overwrite the canvas.
                    const snapshotCanvas = document.createElement('canvas')
                    snapshotCanvas.width  = canvas.width
                    snapshotCanvas.height = canvas.height
                    const snapCtx = snapshotCanvas.getContext('2d')
                    if (snapCtx) {
                        snapCtx.drawImage(canvas, 0, 0)
                    }

                    // Normalise corner coordinates if detector canvas size differs from snapshot
                    const scaleX = snapshotCanvas.width  / imageData.width
                    const scaleY = snapshotCanvas.height / imageData.height
                    let normalizedCorners = code.location
                    if (Math.abs(scaleX - 1.0) > 0.001 || Math.abs(scaleY - 1.0) > 0.001) {
                        const scalePt = (pt) => pt ? { x: pt.x * scaleX, y: pt.y * scaleY } : pt
                        normalizedCorners = {
                            topLeftCorner:               scalePt(code.location.topLeftCorner),
                            topRightCorner:              scalePt(code.location.topRightCorner),
                            bottomRightCorner:           scalePt(code.location.bottomRightCorner),
                            bottomLeftCorner:            scalePt(code.location.bottomLeftCorner),
                            topRightFinderPattern:       scalePt(code.location.topRightFinderPattern),
                            topLeftFinderPattern:        scalePt(code.location.topLeftFinderPattern),
                            bottomLeftFinderPattern:     scalePt(code.location.bottomLeftFinderPattern),
                            bottomRightAlignmentPattern: scalePt(code.location.bottomRightAlignmentPattern),
                        }
                    }

                    // ── Step 2: Crop & enhance before uploading ──────────────────────────────
                    // Instead of sending the full 1920×1080 frame (~3 MB PNG), crop to just
                    // the QR bounding box with 22 % padding, apply a sharpening convolution,
                    // and encode as JPEG.  Drops upload from ~3 MB → ~40 KB.

                    const pts = [
                        normalizedCorners.topLeftCorner,
                        normalizedCorners.topRightCorner,
                        normalizedCorners.bottomRightCorner,
                        normalizedCorners.bottomLeftCorner,
                    ].filter(Boolean)

                    let cropX = 0, cropY = 0, cropW = snapshotCanvas.width, cropH = snapshotCanvas.height
                    let croppedCorners = normalizedCorners

                    if (pts.length === 4) {
                        const xs = pts.map(p => p.x)
                        const ys = pts.map(p => p.y)
                        const minX = Math.min(...xs)
                        const maxX = Math.max(...xs)
                        const minY = Math.min(...ys)
                        const maxY = Math.max(...ys)
                        const qrW = maxX - minX
                        const qrH = maxY - minY
                        const pad = Math.max(qrW, qrH) * 0.22  // 22 % padding each side

                        cropX = Math.max(0, Math.round(minX - pad))
                        cropY = Math.max(0, Math.round(minY - pad))
                        const cropX2 = Math.min(snapshotCanvas.width,  Math.round(maxX + pad))
                        const cropY2 = Math.min(snapshotCanvas.height, Math.round(maxY + pad))
                        cropW = cropX2 - cropX
                        cropH = cropY2 - cropY

                        // Remap corners relative to crop origin so backend rectification is accurate
                        const remapPt = (pt) => pt ? { x: pt.x - cropX, y: pt.y - cropY } : pt
                        croppedCorners = {
                            topLeftCorner:              remapPt(normalizedCorners.topLeftCorner),
                            topRightCorner:             remapPt(normalizedCorners.topRightCorner),
                            bottomRightCorner:          remapPt(normalizedCorners.bottomRightCorner),
                            bottomLeftCorner:           remapPt(normalizedCorners.bottomLeftCorner),
                            topRightFinderPattern:      remapPt(normalizedCorners.topRightFinderPattern),
                            topLeftFinderPattern:       remapPt(normalizedCorners.topLeftFinderPattern),
                            bottomLeftFinderPattern:    remapPt(normalizedCorners.bottomLeftFinderPattern),
                            bottomRightAlignmentPattern:remapPt(normalizedCorners.bottomRightAlignmentPattern),
                        }
                    }

                    // Draw the cropped region into a work canvas
                    const workCanvas = document.createElement('canvas')
                    workCanvas.width  = cropW
                    workCanvas.height = cropH
                    const wCtx = workCanvas.getContext('2d', { willReadFrequently: true })
                    if (snapCtx) {
                        wCtx.drawImage(snapshotCanvas, cropX, cropY, cropW, cropH, 0, 0, cropW, cropH)
                    }

                    // ── Unsharp-mask sharpening convolution ─────────────────────────────────
                    // Compensates for soft focus / motion blur that causes body RS decode to
                    // flip bits across the threshold.  Kernel: identity + high-pass boost.
                    try {
                        const imgData = wCtx.getImageData(0, 0, cropW, cropH)
                        const src = imgData.data
                        const dst = new Uint8ClampedArray(src.length)
                        const w = cropW, h = cropH

                        // 3×3 unsharp kernel  (center = 9, ring = -1, sum = 1 after /9 normalisation)
                        // Equivalent to: sharpened = original + 0.5*(original - gaussian_blur)
                        const kern = [0, -1, 0, -1, 5, -1, 0, -1, 0]  // Laplacian sharpen

                        for (let y = 1; y < h - 1; y++) {
                            for (let x = 1; x < w - 1; x++) {
                                const idx = (y * w + x) * 4
                                for (let c = 0; c < 3; c++) {   // R, G, B only
                                    let v = 0
                                    for (let ky = -1; ky <= 1; ky++) {
                                        for (let kx = -1; kx <= 1; kx++) {
                                            const ki = (ky + 1) * 3 + (kx + 1)
                                            const ni = ((y + ky) * w + (x + kx)) * 4
                                            v += src[ni + c] * kern[ki]
                                        }
                                    }
                                    dst[idx + c] = Math.min(255, Math.max(0, v))
                                }
                                dst[idx + 3] = 255  // alpha
                            }
                        }
                        // Copy border pixels unchanged
                        for (let y = 0; y < h; y++) {
                            for (let x = 0; x < w; x++) {
                                if (y === 0 || y === h - 1 || x === 0 || x === w - 1) {
                                    const idx = (y * w + x) * 4
                                    dst[idx]     = src[idx]
                                    dst[idx + 1] = src[idx + 1]
                                    dst[idx + 2] = src[idx + 2]
                                    dst[idx + 3] = 255
                                }
                            }
                        }
                        wCtx.putImageData(new ImageData(dst, w, h), 0, 0)
                    } catch (_) {
                        // If sharpening fails (e.g. cross-origin canvas taint), continue with unsharpened crop
                    }

                    // ── Encode as JPEG and dispatch ─────────────────────────────────────────
                    const targetCanvas = workCanvas
                    targetCanvas.toBlob((blob) => {
                        if (blob) {
                            if (DEV) {
                                console.log('[QR Scanner] Cropped+sharpened blob:', {
                                    type: blob.type,
                                    size: blob.size,
                                    cropW, cropH,
                                    originalW: snapshotCanvas.width,
                                    originalH: snapshotCanvas.height,
                                    ratio: Math.round((1 - blob.size / (snapshotCanvas.width * snapshotCanvas.height * 0.75)) * 100) + '% smaller'
                                })
                            }
                            Promise.resolve(onQRDetectedRef.current({
                                blob,
                                rawQrData: code.data,
                                corners: croppedCorners,
                                version: code.version,
                                metrics: {
                                    video: videoDims,
                                    canvas: canvasDims,
                                    blobWidth: cropW,
                                    blobHeight: cropH,
                                    devicePixelRatio: dpr,
                                    scaleX,
                                    scaleY
                                }
                            }))
                                .finally(() => {
                                    isProcessingRef.current = false
                                })
                        } else {
                            isProcessingRef.current = false
                        }
                    }, 'image/jpeg', 0.92)

                }
            } else if (!code) {
                setBoundingBox(null)
            }

        } catch (err) {
            console.error('[QR Scanner] Frame scan error:', err)
        }

        if (streamRef.current) {
            animationFrameRef.current = requestAnimationFrame(scanFrame)
        }
    }, [])

    const startScanning = useCallback(async () => {
        try {
            if (DEV) console.log('[QR Scanner] Starting camera access...')
            setError(null)
            setBoundingBox(null)

            // Clean up any existing stream before acquiring a new one
            if (streamRef.current) {
                streamRef.current.getTracks().forEach(track => track.stop())
                streamRef.current = null
            }

            if (!window.isSecureContext) {
                throw new Error('Camera requires HTTPS or localhost.')
            }

            if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
                throw new Error('Camera API not supported in this browser')
            }

            const cameraConfigs = [
                { facingMode: 'environment', width: { ideal: 1920 }, height: { ideal: 1080 } },
                { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } },
                { facingMode: 'environment' },
                { facingMode: 'user', width: { ideal: 1920 }, height: { ideal: 1080 } },
                { facingMode: 'user', width: { ideal: 1280 }, height: { ideal: 720 } },
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

            if (DEV) console.log('[QR Scanner] Camera access granted')
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
    }, [scanFrame])

    useEffect(() => {
        if (DEV) console.log('[QR Scanner] Hook activated:', isActive)

        if (!isActive) {
            stopScanning()
            return
        }

        startScanning()

        return () => {
            if (DEV) console.log('[QR Scanner] Cleaning up...')
            stopScanning()
        }
    }, [isActive, startScanning, stopScanning])

    const clearCooldown = useCallback(() => {
        lastScannedDataRef.current = null
        lastScannedTimeRef.current = 0
    }, [])

    const reset = () => {
        setError(null)
        setBoundingBox(null)
        clearCooldown()
        isProcessingRef.current = false
        if (isActive) {
            if (!streamRef.current) {
                startScanning()
            } else if (!animationFrameRef.current) {
                animationFrameRef.current = requestAnimationFrame(scanFrame)
            }
        }
    }

    return {
        videoRef,
        canvasRef,
        error,
        isScanning,
        boundingBox,
        reset,
        stopScanning,
        clearCooldown,
    }
}
