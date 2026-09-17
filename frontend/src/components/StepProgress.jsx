import { Check } from 'lucide-react'
import './StepProgress.css'

function StepProgress({ steps = [], currentStep = 1, isComplete = false, className = '' }) {
  if (!steps || steps.length === 0) return null

  // Normalize steps to { id, label }
  const normalizedSteps = steps.map((step, idx) => {
    if (typeof step === 'string') {
      return { id: idx + 1, label: step, shortLabel: step }
    }
    return {
      id: step.id ?? idx + 1,
      label: step.label,
      shortLabel: step.shortLabel || step.label
    }
  })

  const currentStepObj = normalizedSteps[currentStep - 1] || normalizedSteps[0]

  return (
    <nav aria-label="Workflow progress" className={`step-progress-nav ${className}`}>
      {/* Desktop & Tablet Step Progress */}
      <ol className="step-list desktop-steps">
        {normalizedSteps.map((step, index) => {
          const stepNum = index + 1
          const isCompleted = isComplete ? stepNum <= currentStep : stepNum < currentStep
          const isCurrent = !isComplete && stepNum === currentStep

          let stepStatusClass = 'upcoming'
          if (isCompleted) stepStatusClass = 'completed'
          if (isCurrent) stepStatusClass = 'current'

          return (
            <li
              key={step.id}
              className={`step-item ${stepStatusClass}`}
              aria-current={isCurrent ? 'step' : undefined}
            >
              <div className="step-indicator-wrapper">
                <span className="step-indicator" aria-hidden="true">
                  {isCompleted ? <Check size={14} strokeWidth={2.5} /> : stepNum}
                </span>
                {index < normalizedSteps.length - 1 && (
                  <div
                    className={`step-connector ${isComplete || stepNum < currentStep ? 'completed' : ''}`}
                    aria-hidden="true"
                  />
                )}
              </div>
              <span className="step-label">{step.label}</span>
            </li>
          )
        })}
      </ol>

      {/* Mobile Compact Progress Bar (<= 640px) */}
      <div className="mobile-step-summary" aria-hidden="true">
        <div className="mobile-step-header">
          <span className="mobile-step-counter">
            Step {currentStep} of {normalizedSteps.length}
          </span>
          <span className="mobile-step-title">{currentStepObj.label}</span>
        </div>
        <div className="mobile-step-bar">
          <div
            className="mobile-step-progress"
            style={{ width: `${(currentStep / normalizedSteps.length) * 100}%` }}
          />
        </div>
      </div>
    </nav>
  )
}

export default StepProgress
