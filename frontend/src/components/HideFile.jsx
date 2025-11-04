import { useState } from 'react'
import axios from 'axios'
import './HideFile.css'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000'

function HideFile() {
  const [image, setImage] = useState(null)
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const [downloadId, setDownloadId] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess(false)

    if (!image || !file) {
      setError('Please select both an image and a file to hide')
      return
    }

    setLoading(true)

    try {
      const formData = new FormData()
      formData.append('image', image)
      formData.append('file', file)

      const response = await axios.post(`${API_URL}/api/hide`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })

      setDownloadId(response.data.download_id)
      setSuccess(true)
      setImage(null)
      setFile(null)
      // Reset file inputs
      document.getElementById('image-input').value = ''
      document.getElementById('file-input').value = ''
    } catch (err) {
      setError(err.response?.data?.error || 'An error occurred while hiding the file')
    } finally {
      setLoading(false)
    }
  }

  const handleDownload = () => {
    window.open(`${API_URL}/api/download/${downloadId}`, '_blank')
  }

  return (
    <div className="hide-file">
      <h2>Hide a File in an Image</h2>
      <p className="description">
        Upload an image and a file. The file will be securely hidden within the image using steganography.
      </p>

      {!success ? (
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="image-input">Select Image (PNG, JPG, JPEG, BMP)</label>
            <input
              id="image-input"
              type="file"
              accept="image/png,image/jpeg,image/bmp"
              onChange={(e) => setImage(e.target.files[0])}
              required
            />
            {image && <p className="file-name">Selected: {image.name}</p>}
          </div>

          <div className="form-group">
            <label htmlFor="file-input">Select File to Hide</label>
            <input
              id="file-input"
              type="file"
              onChange={(e) => setFile(e.target.files[0])}
              required
            />
            {file && <p className="file-name">Selected: {file.name}</p>}
          </div>

          {error && <div className="error-message">{error}</div>}

          <button type="submit" disabled={loading} className="submit-button">
            {loading ? 'Processing...' : 'Hide File'}
          </button>
        </form>
      ) : (
        <div className="success-card">
          <div className="success-icon">✅</div>
          <h3>File Hidden Successfully!</h3>
          <p>Your file has been securely hidden in the image.</p>
          <button onClick={handleDownload} className="download-button">
            📥 Download Image
          </button>
          <button
            onClick={() => {
              setSuccess(false)
              setDownloadId('')
            }}
            className="new-button"
          >
            Hide Another File
          </button>
        </div>
      )}
    </div>
  )
}

export default HideFile
