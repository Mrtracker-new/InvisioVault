import { useState } from 'react'
import { ShieldCheck, Lock, EyeOff, Layers, QrCode, Cpu, AlertTriangle, ChevronDown, ChevronUp, FileCode, CheckCircle2 } from 'lucide-react'
import './SeoContent.css'

const FAQ_ITEMS = [
  {
    q: 'What is InvisioVault?',
    a: 'InvisioVault is an open-source, privacy-first cryptographic application that enables hiding confidential files and messages inside ordinary carriers like images, PDFs, videos, or QR codes using universal polyglot files and edge-adaptive steganography.'
  },
  {
    q: 'Can I hide any file type inside any format?',
    a: "Yes. InvisioVault's Universal Polyglot feature allows any file (ZIP archives, documents, executables) to be concatenated and offset-patched into any carrier (images, audio, PDF, video) while remaining completely functional in standard viewers."
  },
  {
    q: 'How are files protected inside InvisioVault?',
    a: 'Optional passwords derive cryptographic keys using PBKDF2-HMAC-SHA256 with 480,000 iterations, followed by authenticated Fernet encryption (AES-128-CBC with HMAC-SHA256 integrity verification).'
  },
  {
    q: 'Does InvisioVault store my files on the server?',
    a: 'No. InvisioVault operates a strict zero-retention, stateless policy. Uploaded files and processing buffers are automatically erased immediately upon download or request completion.'
  },
  {
    q: 'Will hidden data survive if I share images on WhatsApp, Twitter, or Discord?',
    a: 'No. Social media and messaging platforms aggressively recompress images to lossy JPEG or WebP, destroying least-significant bit information. To preserve steganographic payloads, always send carrier images as uncompressed raw files or documents.'
  }
]

export default function SeoContent() {
  const [openFaq, setOpenFaq] = useState(null)

  const toggleFaq = (index) => {
    setOpenFaq(openFaq === index ? null : index)
  }

  return (
    <section className="seo-content" aria-label="Technical Documentation and Frequently Asked Questions">
      {/* Educational Architecture Grid */}
      <div className="seo-header">
        <h2 className="seo-main-title">Engineering Covert Communication &amp; Cryptography</h2>
        <p className="seo-main-subtitle">
          InvisioVault bridges low-level binary format manipulation with modern authenticated cryptography.
        </p>
      </div>

      <div className="seo-cards-grid">
        <article className="seo-card">
          <div className="seo-card-icon">
            <EyeOff size={24} />
          </div>
          <h3>Detection-Resistant LSB Matching</h3>
          <p>
            Standard steganography replaces least-significant bits, creating a detectable statistical skew known as the Pairs of Values (PoV) effect. InvisioVault implements <strong>LSB matching (±1 random drift)</strong> combined with <strong>Sobel edge gradient convolution</strong> to target high-frequency visual textures where human perception and statistical detectors are blind.
          </p>
          <div className="seo-card-tag">Reed-Solomon RS(255, 223) ECC</div>
        </article>

        <article className="seo-card">
          <div className="seo-card-icon">
            <Layers size={24} />
          </div>
          <h3>Universal Polyglot Engineering</h3>
          <p>
            A polyglot file satisfies two distinct file format parsers simultaneously. Image and media readers parse metadata from byte 0, whereas ZIP archive decoders seek backward from the <strong>End of Central Directory (EOCD)</strong>. InvisioVault uses zero-copy <code>mmap</code> binary offset patching to rewrite internal ZIP relative pointers, producing seamless dual-format files.
          </p>
          <div className="seo-card-tag">In-Memory Offset Recalculation</div>
        </article>

        <article className="seo-card">
          <div className="seo-card-icon">
            <QrCode size={24} />
          </div>
          <h3>Double-Agent QR Steganography</h3>
          <p>
            Standard phone camera scanners see an ordinary, benign URL. By encapsulating encrypted secrets within <strong>RFC 3986 URL fragments (<code>#IVDATA:</code>)</strong>, host servers never receive the secret in HTTP requests. Only InvisioVault isolates the fragment, derives keys with 480k PBKDF2 iterations, and decrypts the hidden message.
          </p>
          <div className="seo-card-tag">RFC 3986 URI Fragment Shield</div>
        </article>
      </div>

      {/* Carrier Degradation Warning Callout */}
      <div className="carrier-warning-banner" role="alert">
        <div className="warning-icon-wrapper">
          <AlertTriangle size={24} />
        </div>
        <div className="warning-text">
          <h4>Carrier Degradation Notice for Social Media</h4>
          <p>
            Lossy image recompression algorithms (used by WhatsApp, Twitter/X, Discord, and Instagram) permanently destroy least-significant bit information.
            To preserve steganographic payloads, <strong>always transmit carrier files as uncompressed documents or raw files</strong>.
          </p>
        </div>
      </div>

      {/* Supported Carrier Matrix */}
      <div className="spec-table-container">
        <h3 className="spec-table-title">Carrier Format &amp; Cryptographic Specifications</h3>
        <div className="table-responsive">
          <table className="spec-table">
            <thead>
              <tr>
                <th scope="col">Carrier Format</th>
                <th scope="col">Hiding Mechanism</th>
                <th scope="col">Cipher / MAC</th>
                <th scope="col">Key Derivation</th>
                <th scope="col">Max Payload</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>PNG, BMP</strong> (Lossless)</td>
                <td>Sobel LSB Matching (±1)</td>
                <td>Fernet (AES-128-CBC + HMAC-SHA256)</td>
                <td>PBKDF2 (480,000 iter)</td>
                <td>3 bits / pixel (~12.5% of carrier)</td>
              </tr>
              <tr>
                <td><strong>PDF, MP4, MP3, JPG</strong></td>
                <td>Polyglot EOCD Offset Patching</td>
                <td>AES-256 (Optional ZIP encryption)</td>
                <td>PBKDF2-HMAC-SHA256</td>
                <td>Up to 50 MB</td>
              </tr>
              <tr>
                <td><strong>QR Barcode</strong></td>
                <td>Fragment (#IVDATA:) / Visual Mask</td>
                <td>Fernet (AES-128-CBC + HMAC-SHA256)</td>
                <td>PBKDF2 (480,000 iter)</td>
                <td>Up to 2,953 bytes (Version 40-L)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Accessible FAQ Accordion */}
      <div className="faq-container">
        <h3 className="faq-section-title">Frequently Asked Questions</h3>
        <div className="faq-list">
          {FAQ_ITEMS.map((item, idx) => {
            const isOpen = openFaq === idx
            return (
              <div key={idx} className={`faq-item ${isOpen ? 'open' : ''}`}>
                <button
                  className="faq-question-btn"
                  onClick={() => toggleFaq(idx)}
                  aria-expanded={isOpen}
                  aria-controls={`faq-answer-${idx}`}
                  id={`faq-btn-${idx}`}
                >
                  <span>{item.q}</span>
                  {isOpen ? <ChevronUp size={18} aria-hidden="true" /> : <ChevronDown size={18} aria-hidden="true" />}
                </button>
                <div
                  id={`faq-answer-${idx}`}
                  className="faq-answer-panel"
                  role="region"
                  aria-labelledby={`faq-btn-${idx}`}
                  hidden={!isOpen}
                >
                  <p>{item.a}</p>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Transparency & Security Links */}
      <div className="seo-footer-links">
        <p>
          <ShieldCheck size={16} className="inline-icon" /> <strong>Zero Retention:</strong> Files are processed statelessly in memory and purged immediately post-download.
        </p>
        <div className="links-group">
          <a href="https://github.com/Mrtracker-new/InvisioVault" target="_blank" rel="noopener noreferrer">
            <FileCode size={14} className="inline-icon" /> View Source on GitHub
          </a>
          <span>•</span>
          <a href="/.well-known/security.txt">security.txt</a>
          <span>•</span>
          <a href="/humans.txt">humans.txt</a>
        </div>
      </div>
    </section>
  )
}
