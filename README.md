# 🔐 HashDrop

**HashDrop** is a high-security file-sharing platform where users can upload files in a hashed format. Admins control access, and OTP verification ensures secure downloads.

> **Note:** This is a group project developed by **Rucha, Shalaka (lead), Rachel, and Sanjana**. The platform is **not yet fully responsive on mobile**.

## 🚀 Features
- **Secure File Uploads** - Files are stored in hashed form.
- **Admin Approval** - Uploads & downloads require admin permission.
- **OTP Verification** - Extra layer of security for downloads.
- **Activity Logs** - Track file uploads and actions.

## 🛠 Technologies Used
- **Backend**: Flask (Python)
- **Database**: MongoDB
- **Frontend**: HTML, CSS, JavaScript
- **Security**: CryptoJS for hashing

## 📦 Installation
### 1️⃣ Clone the Repository
```sh
git clone https://github.com/your-username/hashdrop.git
cd hashdrop
```

### 2️⃣ Set Up a Virtual Environment
```sh
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

### 3️⃣ Install Dependencies
```sh
pip install -r requirements.txt
```

### 4️⃣ Configure Environment Variables
Create a `.env` file and add the required credentials:
```sh
echo "MONGO_URI=your_mongo_connection_string" >> .env
echo "SECRET_KEY=your_secret_key" >> .env
```

### 5️⃣ Run the Application
```sh
python app.py
```

## 🚀 Deployment
```sh
# Deploy using Gunicorn
gunicorn -b 0.0.0.0:$PORT wsgi:app
```

