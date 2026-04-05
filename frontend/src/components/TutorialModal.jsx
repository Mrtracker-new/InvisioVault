import { useState, useEffect, useCallback } from 'react'
import './TutorialModal.css'

const TABS = [
  { id: 'stego', label: 'Steganography', icon: '🖼️' },
  { id: 'polyglot', label: 'Polyglot', icon: '🔗' },
  { id: 'security', label: 'Security', icon: '🔒' },
]

const STEGO_HIDE_STEPS = [
  { num: 1, title: 'Select Cover Image', desc: 'Pick a PNG, JPG, or BMP image — this will be the innocent-looking carrier of your hidden data.' },
  { num: 2, title: 'Choose Secret File', desc: 'Select any file you want to conceal inside the cover image.' },
  { num: 3, title: 'Set a Password', desc: 'Optionally add a password to encrypt your hidden data for an extra layer of security.' },
  { num: 4, title: 'Hide & Download', desc: 'Click "Hide File" to generate the steganographic image, then download it. It looks completely normal!' },
]

const STEGO_EXTRACT_STEPS = [
  { num: 1, title: 'Upload Stego Image', desc: 'Select the steganographic image that contains the hidden file.' },
  { num: 2, title: 'Enter Password', desc: 'Provide the password if one was used during the hiding process.' },
  { num: 3, title: 'Extract & Download', desc: 'Click "Extract File" to retrieve and download your hidden data.' },
]

const POLYGLOT_STEPS = [
  { num: 1, title: 'Select Cover File', desc: 'Choose any file — image, PDF, or ZIP — that will serve as the visible outer layer.' },
  { num: 2, title: 'Choose Secret File', desc: 'Pick the file you want embedded and hidden within the cover.' },
  { num: 3, title: 'Add Encryption', desc: 'Optionally enter a password to encrypt the embedded payload.' },
  { num: 4, title: 'Create & Download', desc: 'Click "Create Polyglot" to merge both files. The result acts as a normal cover file but holds your secret.' },
]

const SECURITY_TIPS = [
  { icon: '🔑', title: 'Use Strong Passwords', desc: 'Combine uppercase, lowercase, numbers, and symbols. Longer is stronger.' },
  { icon: '🛡️', title: 'Guard Your Images', desc: 'Anyone with both the stego image and the password can extract the hidden data.' },
  { icon: '🧪', title: 'Test Before Sending', desc: 'Always do a round-trip test — hide then extract — before sending to anyone.' },
  { icon: '📐', title: 'Use High-Resolution Covers', desc: 'Larger images have more pixel capacity, making hidden data harder to detect statistically.' },
]

function StepCard({ num, title, desc }) {
  return (
    <div className="tm-step-card">
      <div className="tm-step-num" aria-hidden="true">{num}</div>
      <div className="tm-step-body">
        <p className="tm-step-title">{title}</p>
        <p className="tm-step-desc">{desc}</p>
      </div>
    </div>
  )
}

function TipCard({ icon, title, desc }) {
  return (
    <div className="tm-tip-card">
      <span className="tm-tip-icon" aria-hidden="true">{icon}</span>
      <div className="tm-tip-body">
        <p className="tm-tip-title">{title}</p>
        <p className="tm-tip-desc">{desc}</p>
      </div>
    </div>
  )
}

function TutorialModal({ isOpen, onClose }) {
  const [activeTab, setActiveTab] = useState('stego')

  const handleKeyDown = useCallback(
    (e) => {
      if (e.key === 'Escape') onClose()
    },
    [onClose]
  )

  useEffect(() => {
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown)
      document.body.style.overflow = 'hidden'
    }
    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      document.body.style.overflow = ''
    }
  }, [isOpen, handleKeyDown])

  if (!isOpen) return null

  return (
    <div
      className="tm-overlay"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="How to use InvisioVault"
    >
      <div
        className="tm-panel"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="tm-header">
          <div className="tm-header-text">
            <h2 className="tm-title">How to Use InvisioVault</h2>
            <p className="tm-subtitle">Select a topic below to get started</p>
          </div>
          <button
            className="tm-close"
            onClick={onClose}
            aria-label="Close tutorial"
          >
            ✕
          </button>
        </div>

        {/* Tab Bar */}
        <div className="tm-tab-bar" role="tablist" aria-label="Tutorial sections">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              role="tab"
              aria-selected={activeTab === tab.id}
              aria-controls={`tm-panel-${tab.id}`}
              id={`tm-tab-${tab.id}`}
              className={`tm-tab ${activeTab === tab.id ? 'tm-tab--active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              <span className="tm-tab-icon" aria-hidden="true">{tab.icon}</span>
              <span className="tm-tab-label">{tab.label}</span>
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div className="tm-body">

          {/* ── Steganography ── */}
          {activeTab === 'stego' && (
            <div
              id="tm-panel-stego"
              role="tabpanel"
              aria-labelledby="tm-tab-stego"
              className="tm-section"
            >
              <div className="tm-subsection">
                <h3 className="tm-section-heading">
                  <span className="tm-section-badge">Hide</span>
                  Concealing a File
                </h3>
                <div className="tm-steps">
                  {STEGO_HIDE_STEPS.map((s) => (
                    <StepCard key={s.num} {...s} />
                  ))}
                </div>
              </div>

              <div className="tm-divider" aria-hidden="true" />

              <div className="tm-subsection">
                <h3 className="tm-section-heading">
                  <span className="tm-section-badge tm-section-badge--extract">Extract</span>
                  Recovering a File
                </h3>
                <div className="tm-steps">
                  {STEGO_EXTRACT_STEPS.map((s) => (
                    <StepCard key={s.num} {...s} />
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ── Polyglot ── */}
          {activeTab === 'polyglot' && (
            <div
              id="tm-panel-polyglot"
              role="tabpanel"
              aria-labelledby="tm-tab-polyglot"
              className="tm-section"
            >
              <div className="tm-subsection">
                <h3 className="tm-section-heading">
                  <span className="tm-section-badge">Create</span>
                  Embedding a File
                </h3>
                <p className="tm-section-intro">
                  A polyglot file is simultaneously valid as multiple file formats. The output appears to be a normal cover file but secretly contains your embedded payload.
                </p>
                <div className="tm-steps">
                  {POLYGLOT_STEPS.map((s) => (
                    <StepCard key={s.num} {...s} />
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ── Security ── */}
          {activeTab === 'security' && (
            <div
              id="tm-panel-security"
              role="tabpanel"
              aria-labelledby="tm-tab-security"
              className="tm-section"
            >
              <div className="tm-subsection">
                <h3 className="tm-section-heading">
                  <span className="tm-section-badge tm-section-badge--security">Tips</span>
                  Best Practices
                </h3>
                <div className="tm-tips">
                  {SECURITY_TIPS.map((tip) => (
                    <TipCard key={tip.title} {...tip} />
                  ))}
                </div>
              </div>
            </div>
          )}

        </div>

        {/* Footer Note */}
        <div className="tm-footer">
          <span className="tm-footer-icon" aria-hidden="true">🔐</span>
          <p>All processing happens locally — your files are <strong>never stored permanently</strong>.</p>
        </div>
      </div>
    </div>
  )
}

export default TutorialModal
