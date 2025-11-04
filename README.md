# 🔒 InvisioVault

<p align="center">
  <img src="frontend/public/InvisioVault.png" alt="InvisioVault Logo" width="200"/>
</p>

**InvisioVault** is your secret-keeping Swiss Army knife! Hide files in images like a digital magician using steganography, OR go full inception mode with polyglot files that work as TWO formats at once. Built with a slick React frontend and Flask backend because we're fancy like that. 🎩✨

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![React](https://img.shields.io/badge/react-18+-61dafb.svg)

---

## ✨ Features (The Cool Stuff)

### 🖼️ Steganography Mode
- 🎨 **Hide Files in Images**: Upload an image, hide your secrets inside using LSB magic
- 📝 **Text Mode**: Too lazy to create a file? Just type your secrets directly!
- 🔐 **Password Protection**: Encrypt your hidden files because trust no one
- 🗜️ **Auto Compression**: We squeeze your files so they fit better (like packing for a trip)
- 📦 **Any File Type**: PDFs, videos, your crush's photo, memes... we don't judge

### 🔗 Polyglot Mode (The Mind-Bending Stuff)
- 🤯 **True Polyglot Files**: Create files that work as BOTH formats simultaneously
  - It's a JPG! No wait, it's a ZIP! Actually... it's BOTH! 🎭
- 🎪 **Works With Anything**: Images, PDFs, videos, executables - any carrier file you want
- 🔒 **AES-256 Encryption**: Password-protect the ZIP portion (military-grade, baby!)
- 🎬 **Carrier Stays Functional**: Your image still opens, your PDF still works, magic!

### 🎯 General Awesomeness
- 🌙 **Dark Mode by Default**: Because we're not savages
- 👁️ **Password Toggle**: See what you're typing (or hide it from shoulder surfers)
- 📱 **Responsive Design**: Works on your phone, tablet, potato... whatever
- 🚀 **RESTful API**: Integrate it into your own projects if you're feeling adventurous
- ✅ **File Integrity**: Get your files back EXACTLY as you hid them
- 🎮 **Easy Mode**: We made it so simple, your grandma could use it (no offense, grandma)

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
│   │   ├── polyglot.py       # Polyglot file magic
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
│   │   │   ├── ExtractFile.css
│   │   │   ├── Polyglot.jsx
│   │   │   └── Polyglot.css
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
venv\Scripts\activate  # Windows
# source venv/bin/activate  # macOS/Linux
python app.py
```

**Terminal 2** (Frontend):
```bash
cd frontend
npm run dev
```

Then open `http://localhost:5173` in your browser and start hiding stuff!

---

## 🎯 How to Use (It's Almost Too Easy)

### 🖼️ Steganography Mode

**Hiding Stuff:**
1. Pick **🖼️ Steganography** mode
2. Choose **"Hide File"** or **"Hide Text"** (because options are nice)
3. Upload your cover image (the innocent-looking one)
4. Upload your file OR type your secret message
5. (Optional) Add a password because paranoia is healthy
6. Click **"Hide File"**
7. Download your now-suspicious-looking-but-totally-innocent image

**Extracting Stuff:**
1. Upload the image with hidden secrets
2. Enter password if you used one (or watch it fail dramatically)
3. Click **"Extract File"**
4. Your file magically appears! (It's not magic, it's math, but shh...)
5. If it's text, we'll show it on screen like fancy people

### 🔗 Polyglot Mode (The "Wait, What?" Mode)

**Creating a Polyglot:**
1. Pick **🔗 Polyglot** mode
2. Choose **"Create Polyglot"**
3. Upload your carrier file (image, PDF, whatever floats your boat)
4. Upload the file you want to hide
5. (Optional) Add a password for extra security points
6. Download the polyglot file
7. **Mind = Blown:** The file works as BOTH formats!
   - Open it normally → carrier file works fine
   - Rename to `.zip` → hidden file inside!

**Extracting from Polyglot:**
1. Choose **"Extract from Polyglot"**
2. Upload the polyglot file
3. Enter password if needed
4. Get your hidden file back

*Pro tip: You can also just rename the polyglot to `.zip` and use WinRAR/7-Zip like a normal person*

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

## 🛠️ Technology Stack (The Nerdy Bits)

### Backend (The Brain)
- **Flask** - Web framework (lightweight but mighty)
- **Flask-CORS** - So frontend and backend can be friends
- **Pillow** - Image wizardry
- **Cryptography** - For that sweet password encryption
- **Pyzipper** - AES-256 encrypted ZIPs (because standard ZIP encryption is from the Stone Age)
- **Python zlib** - Compression that actually works

### Frontend (The Pretty Face)
- **React** - Because jQuery is so 2010
- **Vite** - Fast as lightning ⚡
- **Axios** - HTTP requests made easy
- **CSS3** - Dark mode, animations, all the eye candy

---

## 🔒 Security Features (We Take This Seriously... Mostly)

- ✅ **File type validation** - No sneaky executables disguised as images
- ✅ **Size limits** - 64 MB max because we're not made of RAM
- ✅ **Path traversal prevention** - Nice try, hacker
- ✅ **Password encryption** - Fernet for stego, AES-256 for polyglots
- ✅ **CORS configuration** - Only talk to people we trust
- ✅ **Secure file naming** - Random tokens because predictable names are boring
- ✅ **Automatic cleanup** - We delete temp files like responsible adults
- ✅ **Data length tracking** - No buffer overflow shenanigans here

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

Now, after actually learning how to code properly, I came back to this project like "Wow... I really made THIS?" So I gave it a complete makeover - separated the frontend and backend, cleaned up the mess, made it actually maintainable, added POLYGLOT FILES (because apparently one way to hide files wasn't enough), threw in some password encryption, made it dark mode because my eyes deserve better, and turned it into something I'm genuinely proud of!

If you're a beginner reading this: **keep going!** Your first project doesn't have to be perfect. Mine certainly wasn't. Just build stuff, break things, and learn along the way. That's how we all started! 💪

Feel free to clone this repo and use it however you want. Who knows, maybe you'll come back in a year and refactor it even better than I did! 😄

*P.S. - If you find any remnants of my "beginner code" still hiding somewhere, just... pretend you didn't see it. Thanks.* 😬
