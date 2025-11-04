import { useState } from 'react'
import axios from 'axios'
import './ExtractFile.css'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000'

function ExtractFile() {
  const [image, setImage] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')

    if (!image) {
      setError('Please select an image with a hidden file')
      return
    }

    setLoading(true)

    try {
      const formData = new FormData()
      formData.append('image', image)

      const response = await axios.post(`${API_URL}/api/extract`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        },
        responseType: 'blob'
      })

      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      
      // Get filename from Content-Disposition header
      const contentDisposition = response.headers['content-disposition']
      let filename = 'extracted_file'
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/)
        if (filenameMatch && filenameMatch[1]) {
          filename = filenameMatch[1].replace(/['"]/g, '')
        }
      }
      
      link.setAttribute('download', filename)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)

      setImage(null)
      document.getElementById('extract-image-input').value = ''
      alert('File extracted successfully!')
    } catch (err) {
      setError(err.response?.data?.error || 'An error occurred while extracting the file')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="extract-file">
      <h2>Extract Hidden File from Image</h2>
      <p className="description">
        Upload an image that contains a hidden file. The file will be extracted and downloaded automatically.
      </p>

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="extract-image-input">Select Image (PNG, JPG, JPEG, BMP)</label>
          <input
            id="extract-image-input"
            type="file"
            accept="image/png,image/jpeg,image/bmp"
            onChange={(e) => setImage(e.target.files[0])}
            required
          />
          {image && <p className="file-name">Selected: {image.name}</p>}
        </div>

        {error && <div className="error-message">{error}</div>}

        <button type="submit" disabled={loading} className="submit-button">
          {loading ? 'Extracting...' : 'Extract File'}
        </button>
      </form>

      <div className="info-box">
        <h4>ℹ️ How it works</h4>
        <ul>
          <li>Upload an image that was created using InvisioVault</li>
          <li>The hidden file will be extracted with its original name</li>
          <li>The file will download automatically to your device</li>
        </ul>
      </div>
    </div>
  )
}

export default ExtractFile
