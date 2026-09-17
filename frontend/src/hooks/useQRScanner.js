/**
 * QR Scanner Hook - Client-side detection with jsQR
 * Provides real-time bounding box feedback and reduces server load.
 *
 * Hardened scanning pipeline (v2):
 *  - 3-frame stability gate: only dispatch when bounding box is stable for ≥ 3 consecutive frames
 *  - Laplacian variance blur gate: skip blurry frames before sending to backend
 *  - PNG (lossless) dispatch: avoids JPEG ±5–8 lx chroma artifacts that corrupt the stego signal
 *  - Adaptive cooldown: 1200 ms after PAYLOAD_DECODE_FAILED (magic found, needs sharper frame)
 *    vs. 3000 ms for normal deduplication
 */
import { useEffect, useRef, useState, useCallback } from 'react'
import jsQR from 'jsqr'

// Only emit verbose logs in development builds (Vite strips import.meta.env.DEV in production)
const DEV = import.meta.env.DEV

// How many consecutive stable frames required before dispatching a scan
const STABILITY_FRAMES_REQUIRED = 3
// Max pixel movement per corner between frames to be considered "stable"
const STABILITY_THRESHOLD_PX = 8
// Minimum grayscale variance across the 64x64 QR crop to consider it sharp/in focus
const MIN_BLUR_SCORE = 500

// Reusable offscreen 64x64 canvas to avoid GC allocations in the scan loop
const proxyCanvas = typeof document !== 'undefined' ? document.createElement('canvas') : null
if (proxyCanvas) {
    proxyCanvas.width = 64
    proxyCanvas.height = 64
}
const proxyCtx = proxyCanvas ? proxyCanvas.getContext('2d', { willReadFrequently: true, colorSpace: 'srgb' }) : null

/**
 * Computes grayscale variance of the 64x64 downscaled QR crop.
 * High variance = sharp, high-contrast black and white modules.
 * Low variance = blurred / motion-smeared / flat frame.
 * Executes in < 0.05ms (4096 pixels).
 */
function computeCropVariance(sourceCanvas, cropX, cropY, cropW, cropH) {
    if (!proxyCtx || cropW <= 0 || cropH <= 0) return { variance: 1000, meanLuma: 128 }
    proxyCtx.drawImage(sourceCanvas, cropX, cropY, cropW, cropH, 0, 0, 64, 64)
    const imgData = proxyCtx.getImageData(0, 0, 64, 64)
    const data = imgData.data
    const len = data.length
    let sum = 0
    let sumSq = 0
    const count = len >>> 2 // 4096 pixels

    for (let i = 0; i < len; i += 4) {
        const luma = 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2]
        sum += luma
        sumSq += luma * luma
    }
    const mean = sum / count
    return {
        variance: (sumSq / count) - (mean * mean),
        meanLuma: mean,
    }
}

/**
 * Compute max corner displacement between two jsQR location objects.
 * Returns Infinity if either is null/undefined.
 */
function cornerDisplacement(locA, locB) {
    if (!locA || !locB) return Infinity
    const keys = ['topLeftCorner', 'topRightCorner', 'bottomLeftCorner', 'bottomRightCorner']
    let maxDist = 0
    for (const k of keys) {
        const a = locA[k]
        const b = locB[k]
        if (!a || !b) return Infinity
        const d = Math.hypot(a.x - b.x, a.y - b.y)
        if (d > maxDist) maxDist = d
    }
    return maxDist
}

export function useQRScanner(isActive, onQRDetected, onError, isPaused = false, options = {}) {
    const { enableAntiMoire = true } = options
    const videoRef = useRef(null)
    const canvasRef = useRef(null)
    const [isScanning, setIsScanning] = useState(false)
    const [error, setError] = useState(null)
    const [boundingBox, setBoundingBox] = useState(null)
    // 'idle' | 'stabilizing' | 'ready' | 'blurry'
    const [stabilityState, setStabilityState] = useState('idle')
    const [antiMoire, setAntiMoire] = useState(enableAntiMoire)
    const antiMoireRef = useRef(antiMoire)
    useEffect(() => {
        antiMoireRef.current = antiMoire
    }, [antiMoire])

    const isPausedRef = useRef(isPaused)
    useEffect(() => {
        isPausedRef.current = isPaused
    }, [isPaused])

    // Hardware camera controls (Torch & Continuous Exposure Mode)
    const [torchSupported, setTorchSupported] = useState(false)
    const [torchOn, setTorchOn] = useState(false)
    const lastMeanLumaRef = useRef(null)

    const streamRef = useRef(null)
    const animationFrameRef = useRef(null)
    const isProcessingRef = useRef(false)

    const toggleTorch = useCallback(async () => {
        if (!streamRef.current || !torchSupported) return
        const track = streamRef.current.getVideoTracks()[0]
        if (!track) return
        try {
            const nextState = !torchOn
            await track.applyConstraints({
                advanced: [{ torch: nextState }]
            })
            setTorchOn(nextState)
        } catch (err) {
            console.warn('[QR Scanner] Failed to toggle torch:', err)
        }
    }, [torchSupported, torchOn])

    // Throttle scanning to avoid CPU spike
    const lastScanTimeRef = useRef(0)
    const SCAN_INTERVAL = 100 // scan every 100ms

    // Deduplication & cooldown to prevent flooding server
    const lastScannedDataRef = useRef(null)
    const lastScannedTimeRef = useRef(0)
    // Normal cooldown: 3 s. After PAYLOAD_DECODE_FAILED shorter adaptive cooldown.
    const SCAN_COOLDOWN_MS = 3000
    const ADAPTIVE_COOLDOWN_MS = 1500

    // Frame stability tracking
    const stableFrameCountRef = useRef(0)
    const lastLocationRef = useRef(null)
    const lastStableDataRef = useRef(null)
    const adaptiveCooldownRef = useRef(false)

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
        setStabilityState('idle')
        stableFrameCountRef.current = 0
        lastLocationRef.current = null
        lastMeanLumaRef.current = null
        setTorchOn(false)
        setTorchSupported(false)
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
            const ctx = canvas.getContext('2d', { willReadFrequently: true, colorSpace: 'srgb' })

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
                setBoundingBox(code.location)

                // ── Stability gate ────────────────────────────────────────────────────
                // Require STABILITY_FRAMES_REQUIRED consecutive frames with the same QR
                // data and bounding box movement < STABILITY_THRESHOLD_PX before dispatch.
                const displacement = cornerDisplacement(lastLocationRef.current, code.location)
                const isSameData = code.data === lastStableDataRef.current

                if (displacement > STABILITY_THRESHOLD_PX || !isSameData) {
                    stableFrameCountRef.current = 1
                    lastLocationRef.current = code.location
                    lastStableDataRef.current = code.data
                    setStabilityState('stabilizing')
                    if (streamRef.current) {
                        animationFrameRef.current = requestAnimationFrame(scanFrame)
                    }
                    return
                }

                stableFrameCountRef.current += 1

                if (stableFrameCountRef.current < STABILITY_FRAMES_REQUIRED) {
                    setStabilityState('stabilizing')
                    if (streamRef.current) {
                        animationFrameRef.current = requestAnimationFrame(scanFrame)
                    }
                    return
                }

                // ── Compute 30% padded crop bounds ───────────────────────────────────
                const pts = [
                    code.location.topLeftCorner,
                    code.location.topRightCorner,
                    code.location.bottomRightCorner,
                    code.location.bottomLeftCorner,
                ].filter(Boolean)

                let cropX = 0, cropY = 0, cropW = canvas.width, cropH = canvas.height
                if (pts.length === 4) {
                    const xs = pts.map(p => p.x)
                    const ys = pts.map(p => p.y)
                    const minX = Math.min(...xs)
                    const maxX = Math.max(...xs)
                    const minY = Math.min(...ys)
                    const maxY = Math.max(...ys)
                    const qrW = maxX - minX
                    const qrH = maxY - minY
                    const pad = Math.max(qrW, qrH) * 0.30  // 30 % padding each side

                    cropX = Math.max(0, Math.round(minX - pad))
                    cropY = Math.max(0, Math.round(minY - pad))
                    const cropX2 = Math.min(canvas.width,  Math.round(maxX + pad))
                    const cropY2 = Math.min(canvas.height, Math.round(maxY + pad))
                    cropW = cropX2 - cropX
                    cropH = cropY2 - cropY
                }

                // ── Blur & Luminance Flicker gate on 64x64 proxy crop ─────────────────
                const { variance: blurScore, meanLuma } = computeCropVariance(canvas, cropX, cropY, cropW, cropH)
                if (blurScore < MIN_BLUR_SCORE) {
                    setStabilityState('blurry')
                    stableFrameCountRef.current = 0
                    if (streamRef.current) {
                        animationFrameRef.current = requestAnimationFrame(scanFrame)
                    }
                    return
                }

                // Luminance Flicker Gate:
                // If camera auto-exposure is hunting, flashing under PWM lighting,
                // or scene brightness abruptly shifts (>15 lx), discard frame and stabilize.
                if (lastMeanLumaRef.current !== null) {
                    const deltaLuma = Math.abs(meanLuma - lastMeanLumaRef.current)
                    if (deltaLuma > 15.0) {
                        lastMeanLumaRef.current = meanLuma
                        setStabilityState('stabilizing')
                        stableFrameCountRef.current = 0
                        if (streamRef.current) {
                            animationFrameRef.current = requestAnimationFrame(scanFrame)
                        }
                        return
                    }
                }
                lastMeanLumaRef.current = meanLuma

                // ── Cooldown deduplication ────────────────────────────────────────────
                const activeCooldown = adaptiveCooldownRef.current ? ADAPTIVE_COOLDOWN_MS : SCAN_COOLDOWN_MS
                const isSameCode = lastScannedDataRef.current === code.data
                const isCoolingDown = now - lastScannedTimeRef.current < activeCooldown

                if (isSameCode && isCoolingDown) {
                    setStabilityState('ready')
                    if (streamRef.current) {
                        animationFrameRef.current = requestAnimationFrame(scanFrame)
                    }
                    return
                }

                setStabilityState('ready')

                if (onQRDetectedRef.current) {
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
                        console.log('[QR Scanner] QR Code stable & sharp — dispatching:', code.data)
                        console.log('[QR Scanner] blurScore:', Math.round(blurScore), '| stableFrames:', stableFrameCountRef.current)
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

                    // ── Step 1: Snapshot the current canvas frame ─────────────────────
                    const snapshotCanvas = document.createElement('canvas')
                    snapshotCanvas.width  = canvas.width
                    snapshotCanvas.height = canvas.height
                    const snapCtx = snapshotCanvas.getContext('2d', { willReadFrequently: true, colorSpace: 'srgb' })
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

                    // ── Step 2: Crop with padding & enforce MIN_OUTPUT_SIZE ──────────
                    // Guarantee adequate pixels per module (PPM) even from a distance.
                    const MIN_OUTPUT_SIZE = 450
                    let targetW = cropW
                    let targetH = cropH
                    let scaleMultiplier = 1.0

                    if (cropW < MIN_OUTPUT_SIZE || cropH < MIN_OUTPUT_SIZE) {
                        scaleMultiplier = Math.max(MIN_OUTPUT_SIZE / cropW, MIN_OUTPUT_SIZE / cropH)
                        targetW = Math.round(cropW * scaleMultiplier)
                        targetH = Math.round(cropH * scaleMultiplier)
                    }

                    // Remap corner coordinates relative to cropped image origin (0,0)
                    // scaled by scaleMultiplier to strictly match workCanvas dimensions.
                    // The backend perspective homography expects coordinates in the space of
                    // the uploaded image blob, not the full camera viewfinder frame.
                    const remapPt = (pt) => pt ? {
                        x: (pt.x - cropX) * scaleMultiplier,
                        y: (pt.y - cropY) * scaleMultiplier,
                    } : pt

                    const croppedCorners = {
                        topLeftCorner:               remapPt(normalizedCorners.topLeftCorner),
                        topRightCorner:              remapPt(normalizedCorners.topRightCorner),
                        bottomRightCorner:           remapPt(normalizedCorners.bottomRightCorner),
                        bottomLeftCorner:            remapPt(normalizedCorners.bottomLeftCorner),
                        topRightFinderPattern:       remapPt(normalizedCorners.topRightFinderPattern),
                        topLeftFinderPattern:        remapPt(normalizedCorners.topLeftFinderPattern),
                        bottomLeftFinderPattern:     remapPt(normalizedCorners.bottomLeftFinderPattern),
                        bottomRightAlignmentPattern: remapPt(normalizedCorners.bottomRightAlignmentPattern),
                    }

                    // Draw the cropped region into a work canvas with Nearest-Neighbor upscaling.
                    // CRITICAL: imageSmoothingEnabled MUST be false to avoid bicubic interpolation,
                    // which blends hard step-function luminance shifts (0 lx vs 50 lx) into smooth gradients.
                    // Nearest-Neighbor guarantees that the exact integer luminance values captured by the sensor
                    // are preserved without bicubic bleeding. The backend Lanczos rectification handles geometry.
                    const workCanvas = document.createElement('canvas')
                    workCanvas.width  = targetW
                    workCanvas.height = targetH
                    const wCtx = workCanvas.getContext('2d', { willReadFrequently: true, colorSpace: 'srgb' })
                    if (snapCtx && wCtx) {
                        // Sizing canvas resets 2D context state to defaults (imageSmoothingEnabled = true).
                        // Force Nearest-Neighbor upscaling explicitly AFTER sizing:
                        wCtx.imageSmoothingEnabled = false
                        if ('imageSmoothingQuality' in wCtx) {
                            wCtx.imageSmoothingQuality = 'low'
                        }

                        // Optical Anti-Aliasing (Moiré Killer):
                        // When scanning a digital screen, LCD/OLED subpixels create high-frequency Moiré fringes.
                        // When the crop bounding box is small (distant scan or small screen display),
                        // apply a subtle Gaussian blur (1.0px) as an optical low-pass filter (OLPF)
                        // to attenuate high-frequency screen subpixels while preserving lower-frequency QR modules.
                        const isSmallCrop = cropW < MIN_OUTPUT_SIZE || cropH < MIN_OUTPUT_SIZE
                        if (antiMoireRef.current && isSmallCrop && 'filter' in wCtx) {
                            wCtx.filter = 'blur(1.0px)'
                        } else {
                            wCtx.filter = 'none'
                        }

                        wCtx.drawImage(snapshotCanvas, cropX, cropY, cropW, cropH, 0, 0, targetW, targetH)
                        wCtx.filter = 'none'
                    }

                    // ── Step 3: Encode as PNG (lossless) and dispatch ─────────────────
                    // PNG avoids JPEG chroma artifacts (±5–8 lx) that corrupt the
                    // 28-lx stego modulation delta and cause bit-flip errors on modules
                    // near the detection threshold.
                    workCanvas.toBlob((blob) => {
                        if (blob) {
                            if (DEV) {
                                console.log('[QR Scanner] Cropped PNG blob:', {
                                    type: blob.type,
                                    size: blob.size,
                                    cropW: targetW,
                                    cropH: targetH,
                                    scaleMultiplier,
                                    originalW: snapshotCanvas.width,
                                    originalH: snapshotCanvas.height,
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
                                    blobWidth: targetW,
                                    blobHeight: targetH,
                                    scaleMultiplier,
                                    devicePixelRatio: dpr,
                                    scaleX,
                                    scaleY,
                                    blurScore: Math.round(blurScore),
                                    stableFrames: stableFrameCountRef.current,
                                }
                            }))
                                .finally(() => {
                                    isProcessingRef.current = false
                                    stableFrameCountRef.current = 0
                                })
                        } else {
                            isProcessingRef.current = false
                        }
                    }, 'image/png')

                }
            } else if (!code) {
                setBoundingBox(null)
                setStabilityState('idle')
                stableFrameCountRef.current = 0
                lastLocationRef.current = null
                lastStableDataRef.current = null
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
            setStabilityState('idle')
            stableFrameCountRef.current = 0
            lastLocationRef.current = null

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
                { facingMode: { ideal: 'environment' }, width: { ideal: 1920 }, height: { ideal: 1080 }, frameRate: { ideal: 30 } },
                { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30 } },
                { facingMode: { ideal: 'environment' } },
                { facingMode: 'user', width: { ideal: 1920 }, height: { ideal: 1080 }, frameRate: { ideal: 30 } },
                { facingMode: 'user', width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30 } },
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

            // Hardware inspection: Torch capability & Continuous Exposure Mode lock
            try {
                const track = stream.getVideoTracks()[0]
                if (track && track.getCapabilities) {
                    const capabilities = track.getCapabilities()
                    setTorchSupported(Boolean(capabilities.torch))

                    if (capabilities.exposureMode && Array.isArray(capabilities.exposureMode) && capabilities.exposureMode.includes('continuous')) {
                        track.applyConstraints({
                            advanced: [{ exposureMode: 'continuous' }]
                        }).catch(err => {
                            if (DEV) console.debug('[QR Scanner] Could not set continuous exposureMode:', err)
                        })
                    }
                }
            } catch (hwErr) {
                if (DEV) console.debug('[QR Scanner] Hardware inspection skipped:', hwErr)
            }

            if (videoRef.current) {
                videoRef.current.srcObject = stream
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

    /**
     * clearCooldown(fast): Reset dedup state.
     * Pass fast=true after a PAYLOAD_DECODE_FAILED to activate the short 1.2 s
     * adaptive cooldown so the user can re-scan quickly.
     */
    const clearCooldown = useCallback((fast = false) => {
        lastScannedDataRef.current = null
        lastScannedTimeRef.current = 0
        adaptiveCooldownRef.current = fast
        stableFrameCountRef.current = 0
        lastLocationRef.current = null
        lastMeanLumaRef.current = null
    }, [])

    const reset = () => {
        setError(null)
        setBoundingBox(null)
        setStabilityState('idle')
        lastMeanLumaRef.current = null
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
        stabilityState,
        reset,
        stopScanning,
        clearCooldown,
        antiMoire,
        setAntiMoire,
        toggleAntiMoire: () => setAntiMoire(prev => !prev),
        torchSupported,
        torchOn,
        toggleTorch,
    }
}
