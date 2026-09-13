import { useState, useEffect } from 'react'
import { Loader2 } from 'lucide-react'
import './ProcessingIndicator.css'

function ProcessingIndicator({
  isActive = false,
  stages = [],
  statusMessage = '',
  className = ''
}) {
  const [currentStageIndex, setCurrentStageIndex] = useState(0)

  useEffect(() => {
    if (!isActive || !stages || stages.length <= 1) {
      setCurrentStageIndex(0)
      return
    }

    // Auto-advance stages smoothly while active
    const interval = setInterval(() => {
      setCurrentStageIndex((prev) => {
        if (prev < stages.length - 1) {
          return prev + 1
        }
        return prev
      })
    }, 700)

    return () => clearInterval(interval)
  }, [isActive, stages])

  if (!isActive) return null

  const displayMessage = statusMessage || (stages.length > 0 ? stages[currentStageIndex] : 'Processing...')
  const progressPercent = stages.length > 0 ? Math.round(((currentStageIndex + 1) / stages.length) * 100) : 60

  return (
    <div
      className={`processing-indicator ${className}`}
      role="status"
      aria-live="polite"
      aria-busy="true"
    >
      <div className="processing-spinner-wrapper" aria-hidden="true">
        <Loader2 className="processing-spinner" size={20} />
      </div>

      <div className="processing-details">
        <p className="processing-message">{displayMessage}</p>

        {stages.length > 1 && (
          <div className="processing-track" aria-hidden="true">
            <div
              className="processing-fill"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        )}
      </div>

      {stages.length > 1 && (
        <span className="processing-stage-counter" aria-hidden="true">
          {currentStageIndex + 1}/{stages.length}
        </span>
      )}
    </div>
  )
}

export default ProcessingIndicator
