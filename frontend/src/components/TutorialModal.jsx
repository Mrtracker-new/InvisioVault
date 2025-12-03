import './TutorialModal.css'

function TutorialModal({ isOpen, onClose }) {
  if (!isOpen) return null

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose}>×</button>
        
        <h2>📖 How to Use InvisioVault</h2>
        
        <div className="tutorial-section">
          <h3>🖼️ Steganography Mode</h3>
          <div className="tutorial-step">
            <h4>Hide File</h4>
            <ol>
              <li>Select a <strong>cover image</strong> (PNG, JPG, or BMP) that will contain your hidden data</li>
              <li>Choose a <strong>secret file</strong> to hide within the image</li>
              <li>Optionally enter a <strong>password</strong> for extra security</li>
              <li>Click <strong>"Hide File"</strong> to generate the steganographic image</li>
              <li>Download your image - it looks normal but contains your hidden file!</li>
            </ol>
          </div>
          
          <div className="tutorial-step">
            <h4>Extract File</h4>
            <ol>
              <li>Upload the <strong>steganographic image</strong> containing the hidden file</li>
              <li>Enter the <strong>password</strong> if you used one during hiding</li>
              <li>Click <strong>"Extract File"</strong> to retrieve your hidden data</li>
              <li>Download the extracted file</li>
            </ol>
          </div>
        </div>

        <div className="tutorial-section">
          <h3>🔗 Polyglot Mode</h3>
          <ol>
            <li>Select a <strong>cover file</strong> (e.g., an image, PDF, or ZIP)</li>
            <li>Choose a <strong>secret file</strong> to embed</li>
            <li>Optionally enter a <strong>password</strong> for encryption</li>
            <li>Click <strong>"Create Polyglot"</strong> to merge the files</li>
            <li>The output file functions as the cover file but contains your hidden data!</li>
          </ol>
        </div>

        <div className="tutorial-section">
          <h3>🔒 Security Tips</h3>
          <ul>
            <li><strong>Use strong passwords</strong> for sensitive files</li>
            <li><strong>Keep your steganographic images secure</strong> - anyone with the image and password can extract the data</li>
            <li><strong>Test your files</strong> by extracting them before sending</li>
            <li><strong>Use high-quality cover images</strong> for better hiding capacity</li>
          </ul>
        </div>

        <div className="tutorial-note">
          <strong>Note:</strong> All processing happens in your browser and backend. Your files are never stored permanently.
        </div>
      </div>
    </div>
  )
}

export default TutorialModal
