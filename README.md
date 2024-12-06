# InvisioVault

InvisioVault is a Flask-based web application that allows users to securely hide any type of file (PDFs, videos, documents, etc.) inside an image. The application compresses files before embedding, enabling it to handle larger files effectively. Hidden files can be extracted later and downloaded in their original format.

---

## Features
- **File Compression**: Efficiently compresses hidden files to maximize storage capacity.
- **File Support**: Supports hiding and extracting any file type, including `.pdf`, `.mp4`, `.txt`, `.apk`, and more.
- **User-Friendly Interface**: Simple upload/download functionality for both embedding and extraction.
- **Security**: Implements Content Security Policy (CSP) headers for enhanced security.

---

## Installation and Setup

Follow the steps below to run InvisioVault locally.

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Clone the Repository
```bash
git clone https://github.com/Mrtracker-new/InvisioVault.git
cd InvisioVault
Install Dependencies
Use the following command to install the required Python packages:

bash
Copy code
pip install -r requirements.txt
Run the Application
bash
Copy code
python app.py
The app will run on http://127.0.0.1:5000. Open this URL in your browser to use the application.

Usage
Hide a File in an Image:

Upload an image (e.g., .png, .jpg) and the file you want to hide.
InvisioVault will embed the file into the image and provide a downloadable output image.
Extract a File from an Image:

Upload the image containing the hidden file.
InvisioVault will extract and decompress the file, offering it for download in its original format.
Folder Structure
bash
Copy code
<project-root>
├── uploads/          # Temporary folder for storing uploaded files
├── templates/        # HTML files for the web interface
├── app.py            # Main Flask application
├── requirements.txt  # List of dependencies
├── README.md         # Project description
└── app.log           # Application log file
Deployment
You can deploy InvisioVault for free on platforms like:

Render
Heroku
Replit
PythonAnywhere
Refer to the respective platform's documentation for detailed steps.

Technologies Used
Backend: Flask (Python)
Frontend: HTML, CSS
Compression: zlib library
Image Processing: PIL (Python Imaging Library)
Contributing
Feel free to fork this repository and submit pull requests. Contributions are welcome!

License
This project is licensed under the MIT License. See the LICENSE file for details.

Contact
For queries or support, feel free to reach out:

Email: rolanlobo901@gmail.com
GitHub: Mrtracker-new
