import { useState, useEffect, useRef } from 'react'
import { UploadCloud, File, Image as ImageIcon, X, RefreshCw, AlertCircle } from 'lucide-react'
import './FileDropzone.css'

function FileDropzone({
  id,
  label,
  accept,
  file,
  onFileSelect,
  onClear,
  helperText,
  error,
  disabled = false,
  required = false,
  compact = false,
  showPreview = true
}) {
  const [isDragOver, setIsDragOver] = useState(false)
  const [thumbnailUrl, setThumbnailUrl] = useState(null)
  const [dropError, setDropError] = useState('')
  const inputRef = useRef(null)
  const dragCounterRef = useRef(0)

  // Manage image preview object URL memory
  useEffect(() => {
    if (!file || !showPreview) {
      setThumbnailUrl(null)
      return
    }

    if (file.type && file.type.startsWith('image/')) {
      const url = URL.createObjectURL(file)
      setThumbnailUrl(url)
      return () => {
        URL.revokeObjectURL(url)
      }
    } else {
      setThumbnailUrl(null)
    }
  }, [file, showPreview])

  const formatFileSize = (bytes) => {
    if (bytes === 0) return '0 B'
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  const getFileExtension = (filename) => {
    if (!filename || !filename.includes('.')) return 'FILE'
    return filename.slice(filename.lastIndexOf('.') + 1).toUpperCase()
  }

  const validateFile = (candidateFile) => {
    if (!candidateFile) return false
    if (!accept) return true

    const acceptedTypes = accept.split(',').map((t) => t.trim().toLowerCase())
    const fileName = candidateFile.name.toLowerCase()
    const fileType = (candidateFile.type || '').toLowerCase()

    const mimeToExt = {
      'image/png': ['.png'],
      'image/jpeg': ['.jpg', '.jpeg'],
      'image/jpg': ['.jpg', '.jpeg'],
      'image/bmp': ['.bmp'],
      'image/webp': ['.webp'],
      'application/pdf': ['.pdf'],
      'application/zip': ['.zip']
    }

    const isValid = acceptedTypes.some((type) => {
      if (type.startsWith('.')) {
        return fileName.endsWith(type)
      }
      if (type.endsWith('/*')) {
        const baseType = type.replace('/*', '')
        return fileType ? fileType.startsWith(baseType) : false
      }
      if (fileType && fileType === type) {
        return true
      }
      const mappedExts = mimeToExt[type]
      if (mappedExts && mappedExts.some((ext) => fileName.endsWith(ext))) {
        return true
      }
      return false
    })

    if (!isValid) {
      setDropError(`Invalid file format. Accepted formats: ${accept}`)
      return false
    }

    setDropError('')
    return true
  }

  const handleDragEnter = (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (disabled) return
    dragCounterRef.current += 1
    if (e.dataTransfer.items && e.dataTransfer.items.length > 0) {
      setIsDragOver(true)
    }
  }

  const handleDragLeave = (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (disabled) return
    dragCounterRef.current -= 1
    if (dragCounterRef.current <= 0) {
      dragCounterRef.current = 0
      setIsDragOver(false)
    }
  }

  const handleDragOver = (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (disabled) return
    e.dataTransfer.dropEffect = 'copy'
  }

  const handleDrop = (e) => {
    e.preventDefault()
    e.stopPropagation()
    if (disabled) return
    dragCounterRef.current = 0
    setIsDragOver(false)

    const droppedFiles = e.dataTransfer.files
    if (droppedFiles && droppedFiles.length > 0) {
      const droppedFile = droppedFiles[0]
      if (validateFile(droppedFile)) {
        onFileSelect(droppedFile)
      }
    }
  }

  const handleInputChange = (e) => {
    const selectedFile = e.target.files?.[0]
    if (selectedFile) {
      if (validateFile(selectedFile)) {
        onFileSelect(selectedFile)
      }
    }
  }

  const handleZoneClick = () => {
    if (disabled) return
    inputRef.current?.click()
  }

  const handleKeyDown = (e) => {
    if (disabled) return
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      inputRef.current?.click()
    }
  }

  const handleClear = (e) => {
    e.stopPropagation()
    if (disabled) return
    if (inputRef.current) inputRef.current.value = ''
    setDropError('')
    onClear()
  }

  const helperId = `${id}-helper`
  const errorId = `${id}-error`
  const activeError = error || dropError

  return (
    <div className={`file-dropzone-wrapper ${compact ? 'compact' : ''} ${disabled ? 'disabled' : ''}`}>
      {label && (
        <label htmlFor={id} className="dropzone-label">
          <span>{label}</span>
          {required && <span className="required-indicator" aria-hidden="true">*</span>}
        </label>
      )}

      {/* Hidden native input for file picking */}
      <input
        ref={inputRef}
        id={id}
        type="file"
        accept={accept}
        disabled={disabled}
        onClick={(e) => { e.target.value = '' }}
        onChange={handleInputChange}
        className="sr-only"
        tabIndex={-1}
      />

      {!file ? (
        /* Empty / Idle / Drag-Over Dropzone */
        <div
          className={`file-dropzone ${isDragOver ? 'drag-over' : ''} ${activeError ? 'has-error' : ''}`}
          onClick={handleZoneClick}
          onKeyDown={handleKeyDown}
          onDragEnter={handleDragEnter}
          onDragLeave={handleDragLeave}
          onDragOver={handleDragOver}
          onDrop={handleDrop}
          role="button"
          tabIndex={disabled ? -1 : 0}
          aria-label={label ? `${label}. Click or drag and drop a file here to upload.` : 'Click or drag and drop a file here to upload.'}
          aria-describedby={[helperText ? helperId : null, activeError ? errorId : null].filter(Boolean).join(' ') || undefined}
        >
          <div className="dropzone-content">
            <div className="dropzone-icon" aria-hidden="true">
              <UploadCloud size={compact ? 24 : 32} />
            </div>
            <div className="dropzone-text">
              <p className="dropzone-prompt">
                <span className="action-link">Click to browse</span> or drag and drop
              </p>
              {helperText && (
                <p id={helperId} className="dropzone-helper">
                  {helperText}
                </p>
              )}
            </div>
          </div>
        </div>
      ) : (
        /* File Selected State with Preview & Badges */
        <div className={`file-selected-card ${activeError ? 'has-error' : ''}`}>
          <div className="file-preview-area">
            {thumbnailUrl ? (
              <div className="thumbnail-container">
                <img src={thumbnailUrl} alt={`Preview of ${file.name}`} className="image-thumbnail" />
              </div>
            ) : (
              <div className="file-icon-container" aria-hidden="true">
                {file.type?.startsWith('image/') ? <ImageIcon size={24} /> : <File size={24} />}
              </div>
            )}
          </div>

          <div className="file-meta">
            <div className="file-name-row">
              <span className="file-name-text" title={file.name}>
                {file.name}
              </span>
              <span className="file-ext-badge">{getFileExtension(file.name)}</span>
            </div>
            <p className="file-size-text">{formatFileSize(file.size)}</p>
          </div>

          <div className="file-actions">
            <button
              type="button"
              className="dropzone-action-btn change-btn"
              onClick={handleZoneClick}
              disabled={disabled}
              title="Change file"
              aria-label="Change selected file"
            >
              <RefreshCw size={16} aria-hidden="true" />
              <span className="btn-label">Change</span>
            </button>
            <button
              type="button"
              className="dropzone-action-btn remove-btn"
              onClick={handleClear}
              disabled={disabled}
              title="Remove file"
              aria-label={`Remove ${file.name}`}
            >
              <X size={18} aria-hidden="true" />
            </button>
          </div>
        </div>
      )}

      {activeError && (
        <p id={errorId} className="dropzone-error-msg" role="alert">
          <AlertCircle size={14} style={{ flexShrink: 0 }} aria-hidden="true" />
          <span>{activeError}</span>
        </p>
      )}
    </div>
  )
}

export default FileDropzone
