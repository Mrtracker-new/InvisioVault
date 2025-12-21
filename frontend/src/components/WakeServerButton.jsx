import { useState, useCallback, useEffect, useRef } from 'react'
import axios from 'axios'
import API_URL from '../config/api'
import './WakeServerButton.css'

// Internal Toast Component for localized notifications
const StatusToast = ({ message, type, isVisible }) => (
  <div className={`status-toast ${type} ${isVisible ? 'visible' : ''}`} role="status">
    <span className="toast-dot"></span>
    {message}
  </div>
)

function WakeServerButton() {
  // --- State Management ---
  const [status, setStatus] = useState('idle') // idle, waking, online, error, cooldown
  const [toast, setToast] = useState({ message: '', type: 'info', visible: false })
  const [cooldownTime, setCooldownTime] = useState(0)
  const [showSuccess, setShowSuccess] = useState(false)

  // Refs for cleanup
  const toastTimer = useRef(null)
  const cooldownTimer = useRef(null)
  const successTimer = useRef(null)

  // --- Helpers ---

  const showToast = useCallback((message, type = 'info', duration = 3000) => {
    if (toastTimer.current) clearTimeout(toastTimer.current)

    setToast({ message, type, visible: true })

    if (duration) {
      toastTimer.current = setTimeout(() => {
        setToast(prev => ({ ...prev, visible: false }))
      }, duration)
    }
  }, [])

  // --- Logic ---

  const startCooldown = useCallback((seconds) => {
    setStatus('cooldown')
    setCooldownTime(seconds)
    showToast(`Connection failed. Retry in ${seconds}s`, 'error', seconds * 1000)

    cooldownTimer.current = setInterval(() => {
      setCooldownTime(prev => {
        if (prev <= 1) {
          clearInterval(cooldownTimer.current)
          setStatus('idle')
          showToast('Ready to retry', 'info', 2000)
          return 0
        }
        return prev - 1
      })
    }, 1000)
  }, [showToast])

  const handleWake = useCallback(async () => {
    // 1. Rate Limiting & Guard Clauses
    if (status === 'waking' || status === 'online' || status === 'cooldown') return

    // 2. State Transition: Waking
    setStatus('waking')
    showToast('Connecting to server...', 'loading', 0) // Persist until success/fail

    try {
      // 3. API Request
      const response = await axios.get(`${API_URL}/api/health`, {
        timeout: 45000,
        validateStatus: status => status === 200
      })

      // 4. Success State
      if (response.status === 200) {
        setStatus('online')
        setShowSuccess(true)
        showToast('Server is Online', 'success', 4000)

        // Hide success checkmark after animation
        successTimer.current = setTimeout(() => {
          setShowSuccess(false)
        }, 2000)

        // Return to idle visual state after 5s but keep server "conceptually" online
        setTimeout(() => setStatus('idle'), 5000)
      }
    } catch (error) {
      console.error('Server Wake Failed:', error)

      // 5. Error Handling & Cooldown triggers
      setStatus('error')

      // Brief error state to show shake animation
      setTimeout(() => {
        startCooldown(5) // 5 second cooldown
      }, 600)
    }
  }, [status, showToast, startCooldown])

  // Keyboard support
  const handleKeyDown = useCallback((e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      handleWake()
    }
  }, [handleWake])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (toastTimer.current) clearTimeout(toastTimer.current)
      if (cooldownTimer.current) clearInterval(cooldownTimer.current)
      if (successTimer.current) clearTimeout(successTimer.current)
    }
  }, [])

  // --- Accessibility Label ---
  const getAriaLabel = () => {
    if (status === 'cooldown') return `System cooling down, wait ${cooldownTime} seconds`
    if (status === 'waking') return 'Connecting to server'
    if (status === 'online') return 'Server is online'
    if (status === 'error') return 'Connection failed'
    return 'Wake up server'
  }

  // Status text helper
  const getStatusText = () => {
    if (status === 'cooldown') return `Wait ${cooldownTime}s`
    if (status === 'waking') return 'Waking...'
    if (status === 'online') return 'Online'
    if (status === 'error') return 'Failed'
    return 'Wake Server'
  }

  return (
    <div className="wake-server-container">
      {/* Toast Notification positioned absolutely relative to container */}
      <StatusToast
        message={toast.message}
        type={toast.type}
        isVisible={toast.visible}
      />

      <button
        className={`power-button ${status}`}
        onClick={handleWake}
        onKeyDown={handleKeyDown}
        disabled={status === 'waking' || status === 'cooldown'}
        aria-label={getAriaLabel()}
        aria-live="polite"
        type="button"
      >
        {/* Background Glow Layer */}
        <span className="glow-layer" aria-hidden="true"></span>

        {/* Loading Spinner (visible only during waking) */}
        {status === 'waking' && (
          <svg className="spinner-ring" viewBox="0 0 50 50" aria-hidden="true">
            <circle
              className="spinner-track"
              cx="25"
              cy="25"
              r="20"
              fill="none"
              strokeWidth="3"
            />
            <circle
              className="spinner-arc"
              cx="25"
              cy="25"
              r="20"
              fill="none"
              strokeWidth="3"
            />
          </svg>
        )}

        {/* Power Icon (Always Visible) */}
        <svg
          className="power-icon"
          viewBox="0 0 24 24"
          aria-hidden="true"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M18.36 6.64a9 9 0 1 1-12.73 0" />
          <line x1="12" y1="2" x2="12" y2="12" />
        </svg>

        {/* Success Checkmark Overlay */}
        {showSuccess && (
          <svg
            className="success-checkmark"
            viewBox="0 0 24 24"
            aria-hidden="true"
            fill="none"
            stroke="currentColor"
            strokeWidth="3"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <polyline points="20 6 9 17 4 12" />
          </svg>
        )}

        {/* Text Label (Desktop Only) */}
        <span className="status-label" aria-hidden="true">
          {getStatusText()}
        </span>
      </button>
    </div>
  )
}

export default WakeServerButton
