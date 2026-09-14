import { useState, useCallback, useEffect, useRef } from 'react'
import { Power, Loader2, Check, AlertCircle } from 'lucide-react'
import axios from 'axios'
import API_URL from '../config/api'
import './WakeServerButton.css'

// Internal Toast Component for localized notifications
const StatusToast = ({ message, type, isVisible }) => (
  <div className={`status-toast ${type} ${isVisible ? 'visible' : ''}`} role="status">
    <span className="toast-dot" aria-hidden="true" />
    <span className="toast-text">{message}</span>
  </div>
)

function WakeServerButton() {
  // State: 'idle' | 'waking' | 'online' | 'error' | 'cooldown'
  const [status, setStatus] = useState('idle')
  const [toast, setToast] = useState({ message: '', type: 'info', visible: false })
  const [cooldownTime, setCooldownTime] = useState(0)
  const [showSuccess, setShowSuccess] = useState(false)

  // Refs for timer cleanup and unmount safety
  const toastTimer = useRef(null)
  const cooldownTimer = useRef(null)
  const successTimer = useRef(null)
  const errorTimer = useRef(null)
  const isMountedRef = useRef(true)

  const showToast = useCallback((message, type = 'info', duration = 3000) => {
    if (toastTimer.current) clearTimeout(toastTimer.current)

    setToast({ message, type, visible: true })

    if (duration) {
      toastTimer.current = setTimeout(() => {
        if (isMountedRef.current) {
          setToast(prev => ({ ...prev, visible: false }))
        }
      }, duration)
    }
  }, [])

  const startCooldown = useCallback((seconds) => {
    if (!isMountedRef.current) return
    setStatus('cooldown')
    setCooldownTime(seconds)
    showToast(`Connection failed. Retry in ${seconds}s`, 'error', seconds * 1000)

    if (cooldownTimer.current) clearInterval(cooldownTimer.current)
    cooldownTimer.current = setInterval(() => {
      setCooldownTime(prev => {
        if (prev <= 1) {
          clearInterval(cooldownTimer.current)
          if (isMountedRef.current) {
            setStatus('idle')
            showToast('Ready to retry', 'info', 2000)
          }
          return 0
        }
        return prev - 1
      })
    }, 1000)
  }, [showToast])

  // Passive initial check on mount — seamlessly detects if server is already running
  useEffect(() => {
    isMountedRef.current = true
    const checkInitialHealth = async () => {
      try {
        const response = await axios.get(`${API_URL}/api/health`, {
          timeout: 2500,
          validateStatus: s => s === 200
        })
        if (isMountedRef.current && response.status === 200) {
          setStatus('online')
        }
      } catch {
        // If asleep or unreachable, stay in 'idle' for manual wake
      }
    }
    checkInitialHealth()
    return () => {
      isMountedRef.current = false
    }
  }, [])

  const handleWake = useCallback(async () => {
    // Guard against multi-clicks while waking or in cooldown
    if (status === 'waking' || status === 'cooldown') return

    setStatus('waking')
    showToast(status === 'online' ? 'Verifying server status...' : 'Connecting to server...', 'loading', 0)

    try {
      const response = await axios.get(`${API_URL}/api/health`, {
        timeout: 45000,
        validateStatus: s => s === 200
      })

      if (isMountedRef.current && response.status === 200) {
        setStatus('online')
        setShowSuccess(true)
        showToast('Server is Online', 'success', 3500)

        if (successTimer.current) clearTimeout(successTimer.current)
        successTimer.current = setTimeout(() => {
          if (isMountedRef.current) {
            setShowSuccess(false)
          }
        }, 2200)
      }
    } catch (error) {
      console.error('Server Wake Failed:', error?.message || error, error?.code || '')
      if (!isMountedRef.current) return

      setStatus('error')
      if (errorTimer.current) clearTimeout(errorTimer.current)
      errorTimer.current = setTimeout(() => {
        if (isMountedRef.current) {
          startCooldown(5)
        }
      }, 500)
    }
  }, [status, showToast, startCooldown])

  // Keyboard support (Enter or Space)
  const handleKeyDown = useCallback((e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      handleWake()
    }
  }, [handleWake])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      isMountedRef.current = false
      if (toastTimer.current) clearTimeout(toastTimer.current)
      if (cooldownTimer.current) clearInterval(cooldownTimer.current)
      if (successTimer.current) clearTimeout(successTimer.current)
      if (errorTimer.current) clearTimeout(errorTimer.current)
    }
  }, [])

  const getAriaLabel = () => {
    if (status === 'cooldown') return `System cooling down, wait ${cooldownTime} seconds`
    if (status === 'waking') return 'Connecting to server'
    if (status === 'online') return 'Server is online. Click to re-check'
    if (status === 'error') return 'Connection failed'
    return 'Wake up server'
  }

  const getStatusText = () => {
    if (status === 'cooldown') return `Wait ${cooldownTime}s`
    if (status === 'waking') return 'Waking...'
    if (status === 'online') return 'Online'
    if (status === 'error') return 'Failed'
    return 'Wake Server'
  }

  return (
    <div className="wake-server-container">
      <StatusToast
        message={toast.message}
        type={toast.type}
        isVisible={toast.visible}
      />

      <button
        className={`power-button ${status} ${showSuccess ? 'success-pop' : ''}`}
        onClick={handleWake}
        onKeyDown={handleKeyDown}
        disabled={status === 'waking' || status === 'cooldown'}
        aria-label={getAriaLabel()}
        aria-live="polite"
        type="button"
      >
        {/* Ambient Backlight Glow Layer */}
        <span className="glow-layer" aria-hidden="true" />

        {/* Tran Mau Tri Tam Prismatic Chromatic Aura (Internal Refracted Light) */}
        <span className={`glass-aura-blob aura-${status}`} aria-hidden="true" />

        {/* Top Curved Specular Lens Reflection */}
        <span className="glass-lens-reflection" aria-hidden="true" />

        {/* Live Status Beacon Dot */}
        <span className={`status-beacon beacon-${status}`} aria-hidden="true">
          <span className="beacon-ping" />
          <span className="beacon-core" />
        </span>

        {/* Dedicated Icon Slot (always in place, never collides with text) */}
        <span className="icon-slot" aria-hidden="true">
          {status === 'waking' ? (
            <Loader2 className="status-icon icon-spin" size={15} />
          ) : showSuccess ? (
            <Check className="status-icon icon-success" size={15} strokeWidth={2.5} />
          ) : status === 'error' ? (
            <AlertCircle className="status-icon icon-error" size={15} />
          ) : (
            <Power className="status-icon icon-power" size={15} strokeWidth={2.2} />
          )}
        </span>

        {/* Responsive Text Label */}
        <span className="status-label">
          {getStatusText()}
        </span>
      </button>
    </div>
  )
}

export default WakeServerButton
