# 🔒 InvisioVault

<p align="center">
  <img src="frontend/public/InvisioVault.png" alt="InvisioVault Logo" width="200"/>
</p>

**Hide your secrets like a pro!** InvisioVault lets you stash files inside images using steganography, OR create mind-bending polyglot files that work as TWO formats at once. It's like magic, but with more React and Flask. ✨

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![React](https://img.shields.io/badge/react-18+-61dafb.svg)

---

## ✨ What Can It Do?

### 🖼️ Steganography Mode
Hide files **inside** images using LSB steganography. Your image looks normal, but it's secretly carrying secret cargo!

- **Hide Files or Text** - Upload a file OR just type your secrets directly
- **Password Protection** - Encrypt your hidden data (trust no one 🔐)
- **Auto Compression** - We squeeze files to fit better
- **Smart Capacity Calculator** - Know before you go! Real-time indicator shows if your file will fit
- **Any File Type** - PDFs, videos, memes... we don't judge

### 🔗 Polyglot Mode
Create files that work as **TWO formats at once**. Open it as an image? Image. Rename to .zip? BAM, hidden files!

- **Any Format Combination** - Images, PDFs, videos, whatever + whatever
- **AES-256 Encryption** - Password protection with military-grade security
- **Carrier Stays Functional** - Your original file works perfectly
- **Zero Manual Work** - We handle compression and polyglot creation automatically

### 🎯 The Nice-to-Haves
- 🌙 **Dark Mode** - Because we respect your retinas
- 👁️ **Password Toggle** - See what you're typing (or hide from shoulder surfers)
- � **Capacity Analysis** - Color-coded progress bars show exactly how much space you're using
- �📱 **Responsive** - Works on phones, tablets, whatever
- 🚀 **RESTful API** - Integrate into your own projects

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+

### Easy Mode (Windows)
Just run the `run.bat` file. It'll start both servers in separate windows!

### Manual Setup

**Backend:**
```bash
cd backend
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Mac/Linux
pip install -r requirements.txt
cp .env.example .env
python app.py
```
Backend runs on `http://localhost:5000`

**Frontend:**
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```
Frontend runs on `http://localhost:5173`

---

## 🎯 How to Use

### Hiding Files in Images
1. Pick **Steganography** mode
2. Choose an image (your innocent cover)
3. Upload a file OR type text
4. Optional: Add password for extra security
5. Check the **capacity indicator** - it'll tell you if it fits!
6. Click "Hide File"
7. Download your suspiciously-normal-looking image

### Creating Polyglot Files
1. Pick **Polyglot** mode
2. Upload carrier file (any format!)
3. Upload file to hide (any format!)
4. Optional: Add password
5. Click create
6. Download your brain-melting dual-format file
7. Open normally = carrier works. Rename to `.zip` = hidden file appears!

---

## 🛠️ Tech Stack

**Backend:** Flask, Pillow, Cryptography, Pyzipper  
**Frontend:** React, Vite, Axios  
**Special Sauce:** LSB Steganography, AES-256 Encryption

---

## 🔒 Security Features

- ✅ File validation (no sneaky stuff)
- ✅ Size limits (64 MB max)
- ✅ Rate limiting (100 req/hour - we bumped it for the capacity calculator!)
- ✅ Password encryption (Fernet + AES-256)
- ✅ Auto cleanup (we're tidy)
- ✅ Path traversal prevention

---

## � New Feature: Interactive Capacity Calculator

Our latest addition shows you **real-time** if your file will fit before hiding it!

- 📈 Visual progress bar with color coding
- ✅ Green: "File will fit comfortably"
- 🟡 Yellow: "High capacity, but you're good"
- 🔴 Red: "Nope, too big buddy"
- 🧮 Shows exact sizes and percentages
- ⚡ Smart debouncing (500ms) to prevent API spam

No more trial-and-error! The calculator tells you upfront if your secret will fit in your carrier.

---

## 📁 Project Structure

```
InvisioVault/
├── backend/              # Flask API
│   ├── api/             # Routes
│   ├── utils/           # Steganography, polyglot magic
│   └── app.py           # Main app
├── frontend/            # React SPA
│   └── src/
│       ├── components/  # HideFile, ExtractFile, Polyglot, CapacityIndicator
│       └── App.jsx
└── run.bat             # Easy start script (Windows)
```

---

## 🤝 Contributing

Pull requests welcome! Just:
1. Fork it
2. Make it better
3. Send a PR with a funny commit message (we appreciate the vibes)

---

## 📜 License

MIT License - do whatever you want with it!

---

## 👨‍💻 Author

**Rolan**  
📧 rolanlobo901@gmail.com  
🐙 [@Mrtracker-new](https://github.com/Mrtracker-new)

---

## ⚠️ Disclaimer

Use responsibly! This is for educational and personal use. Don't hide illegal stuff. The author is not responsible for your shenanigans.

---

## 🎉 Thank You!

**Star ⭐ this repo if you find it useful!**

May your files stay hidden and your secrets stay secret! 🤫

---

## � Fun Fact

This was my **first ever repo**! Looking back at the original code is... an experience. Let's just say past-me had enthusiasm and caffeine, but not much else.

After learning how to actually code, I came back and gave this thing a complete makeover:
- Separated frontend/backend (revolutionary!)
- Added polyglot files (because why not)
- Threw in encryption (security!)
- Made it dark mode (my eyes say thanks)
- Added the capacity calculator (no more guessing games!)

If you're a beginner: **keep building!** Your first project doesn't need to be perfect. Mine definitely wasn't. Just code, break things, and learn! 💪

*P.S. - If you find any ancient code artifacts from the Before Times, just... look away. Thanks.* �
