# 🔒 InvisioVault

<p align="center">
  <img src="frontend/public/InvisioVault.png" alt="InvisioVault Logo" width="200"/>
</p>

**InvisioVault** is a modern, full-stack steganography application that allows you to securely hide files within images using LSB (Least Significant Bit) techniques with compression. Built with a separate React frontend and Flask REST API backend for scalability and maintainability.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![React](https://img.shields.io/badge/react-18+-61dafb.svg)

---

## ✨ Features

- 🎨 **Modern UI**: Beautiful, responsive React interface with dark theme
- 🔐 **Secure Steganography**: Hide any file type within images using LSB encoding
- 🗜️ **Smart Compression**: Automatic file compression for efficient storage
- 📦 **Multiple File Types**: Support for PDFs, videos, documents, archives, and more
- 🚀 **Separate Architecture**: Independent frontend and backend for easy deployment
- 🔄 **RESTful API**: Clean API design for easy integration
- ✅ **File Integrity**: Extract files in their original, unaltered format
- 📱 **Responsive Design**: Works seamlessly on desktop and mobile devices

---

## 🏗️ Project Structure

```
InvisioVault/
├── backend/                    # Flask REST API
│   ├── api/                   # API routes
│   │   └── routes.py         # Endpoint definitions
│   ├── config/               # Configuration
│   │   └── settings.py       # App settings
│   ├── utils/                # Utilities
│   │   ├── steganography.py  # Core steganography logic
│   │   └── validators.py     # File validation
│   ├── app.py                # Flask application factory
│   ├── requirements.txt      # Python dependencies
│   └── .env.example          # Environment variables template
│
├── frontend/                  # React SPA
│   ├── src/
│   │   ├── components/       # React components
│   │   │   ├── HideFile.jsx
│   │   │   ├── HideFile.css
│   │   │   ├── ExtractFile.jsx
│   │   │   └── ExtractFile.css
│   │   ├── App.jsx           # Main application
│   │   ├── App.css           # Global styles
│   │   └── main.jsx          # Entry point
│   ├── package.json          # Node dependencies
│   └── .env.example          # Frontend env template
│
├── .gitignore                # Git ignore rules
└── README.md                 # This file
```

---

## 🚀 Getting Started

### Prerequisites

- **Python** 3.8 or higher
- **Node.js** 16 or higher
- **npm** or **yarn**

### Backend Setup

1. **Navigate to backend directory**:
   ```bash
   cd backend
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv venv
   ```

3. **Activate virtual environment**:
   - Windows: `venv\Scripts\activate`
   - macOS/Linux: `source venv/bin/activate`

4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

5. **Create `.env` file** (copy from `.env.example`):
   ```bash
   cp .env.example .env
   ```

6. **Run the backend**:
   ```bash
   python app.py
   ```
   Backend will run on `http://localhost:5000`

### Frontend Setup

1. **Navigate to frontend directory**:
   ```bash
   cd frontend
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Create `.env` file** (copy from `.env.example`):
   ```bash
   cp .env.example .env
   ```

4. **Run the development server**:
   ```bash
   npm run dev
   ```
   Frontend will run on `http://localhost:5173`

### Quick Start (Both Services)

You can run both backend and frontend simultaneously in separate terminals:

**Terminal 1** (Backend):
```bash
cd backend
python app.py
```

**Terminal 2** (Frontend):
```bash
cd frontend
npm run dev
```

Then open `http://localhost:5173` in your browser.

---

## 🎯 How to Use

### Hiding a File

1. Click on the **"Hide File"** tab
2. Upload an image (PNG, JPG, JPEG, BMP)
3. Upload the file you want to hide
4. Click **"Hide File"**
5. Download the generated image with the hidden file

### Extracting a File

1. Click on the **"Extract File"** tab
2. Upload an image containing a hidden file
3. Click **"Extract File"**
4. The hidden file will download automatically with its original name

---

## 🔌 API Endpoints

### Health Check
```http
GET /api/health
```
Returns API status

### Hide File
```http
POST /api/hide
Content-Type: multipart/form-data

Body:
  - image: Image file
  - file: File to hide

Response:
{
  "success": true,
  "message": "File hidden successfully",
  "download_id": "random_id.png"
}
```

### Download Image
```http
GET /api/download/<download_id>
```
Download the image with hidden file

### Extract File
```http
POST /api/extract
Content-Type: multipart/form-data

Body:
  - image: Image file with hidden data

Response: Binary file download
```

---

## 🛠️ Technology Stack

### Backend
- **Flask** - Web framework
- **Flask-CORS** - Cross-origin resource sharing
- **Pillow** - Image processing
- **Python zlib** - File compression

### Frontend
- **React** - UI library
- **Vite** - Build tool and dev server
- **Axios** - HTTP client
- **CSS3** - Modern styling with animations

---

## 🔒 Security Features

- ✅ File type validation
- ✅ Size limits (64 MB max)
- ✅ Path traversal prevention
- ✅ CORS configuration
- ✅ Secure file naming with secrets module
- ✅ Automatic cleanup of temporary files

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 Environment Variables

### Backend (.env)
```env
FLASK_ENV=development
DEBUG=True
SECRET_KEY=your-secret-key
UPLOAD_FOLDER=uploads
CORS_ORIGINS=http://localhost:5173
PORT=5000
LOG_LEVEL=INFO
```

### Frontend (.env)
```env
VITE_API_URL=http://localhost:5000
```

---

## 📜 License

This project is licensed under the MIT License. Feel free to use, modify, and distribute.

---

## 👨‍💻 Author

**Rolan**
- Email: rolanlobo901@gmail.com
- GitHub: [@Mrtracker-new](https://github.com/Mrtracker-new)

---

## ⚠️ Disclaimer

InvisioVault is intended for educational and personal use. Always ensure ethical and legal compliance when hiding sensitive information. The author is not responsible for any misuse of this software.

---

## 🙏 Acknowledgments

- Built with modern web technologies
- Inspired by the need for simple, secure file hiding
- Thanks to the open-source community

---

## 🎉 Thank You!

Your journey into modern steganography starts here. Let InvisioVault redefine how you secure and share data.

**Star ⭐ this repository if you find it useful!**

---

## 😅 A Funny Little Story (From the Creator)

So... funny story. This was actually my **first ever repo**! 🎉

Back then, I had absolutely NO idea what I was doing. Like, zero. Zilch. Nada. I just woke up one day and thought, "Hey, wouldn't it be cool to hide files in images?" and somehow... this happened? 🤷‍♂️

Honestly, I don't even remember HOW I created it. I was just throwing code at the wall and praying something would stick. The deployment? Pure chaos. The code structure? A beautiful disaster. Everything was held together with duct tape, hope, and probably too much caffeine.

But hey, it worked! (Sort of. Most of the time. When the stars aligned.)

Now, after actually learning how to code properly, I came back to this project like "Wow... I really made THIS?" So I gave it a complete makeover - separated the frontend and backend, cleaned up the mess, made it actually maintainable, and turned it into something I'm genuinely proud of!

If you're a beginner reading this: **keep going!** Your first project doesn't have to be perfect. Mine certainly wasn't. Just build stuff, break things, and learn along the way. That's how we all started! 💪

Feel free to clone this repo and use it however you want. Who knows, maybe you'll come back in a year and refactor it even better than I did! 😄

*P.S. - If you find any remnants of my "beginner code" still hiding somewhere, just... pretend you didn't see it. Thanks.* 😬
