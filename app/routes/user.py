from base64 import urlsafe_b64encode
import base64
from docx2pdf import convert
import hashlib
import io
import json
import mimetypes
import subprocess
from xml.dom.minidom import Document
import cv2
from flask import Blueprint, Response, app, jsonify, render_template, request, redirect, url_for, flash, session
from flask_mail import Message
import magic
from pygments import highlight
import pypandoc
from app import mongo, mail
from bson import ObjectId
import pytz
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from zoneinfo import ZoneInfo  # If using zoneinfo for time zones
from cryptography.fernet import Fernet
from app.utils.helpers import *
from app.utils.encryption import *
import img2pdf
from pygments import highlight
from pygments.lexers import PythonLexer, JsonLexer, HtmlLexer
from pygments.formatters import HtmlFormatter

# Define IST timezone
ist_timezone = pytz.timezone('Asia/Kolkata')

# Get the current IST time
uploaded_at = datetime.now(ist_timezone)

bp = Blueprint('user', __name__)

@bp.route('/user_info', methods=['GET'])
def get_user_info():
    """
    Retrieve current user's name and role
    """
    if 'user_email' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user = mongo.db.users.find_one({
        'email': session['user_email']
    }, {
        'name': 1, 
        'role': 1
    })

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'name': user.get('name', 'Unknown'),
        'role': user.get('role', 'User')
    })

# User Dashboard Route
@bp.route('/dashboard', methods=['GET', 'POST'])
def user_dashboard():
    if 'user_email' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('auth.login'))  # Redirect to the login route

    email = session['user_email']
    user_files = mongo.db.files.find({'uploaded_by': email})  # Fetch user-specific files from the database

    if request.method == 'POST' and 'file' in request.files:
        file = request.files['file']
        if file and file.filename:
            filename = secure_filename(file.filename)
            file_path = os.path.join('uploads', filename)
            file.save(file_path)

            # Save file metadata to the database
            mongo.db.files.insert_one({
                'filename': filename,
                'file_path': file_path,
                'uploaded_by': email,
                'uploaded_at': uploaded_at,
            })

            flash('File uploaded successfully!', 'success')
            return redirect(url_for('user.user_dashboard'))
        else:
            flash('No file selected for upload.', 'danger')

    return render_template('user_dashboard.html', files=user_files)


@bp.route('/request_permission/<file_id>', methods=['POST'])
def request_permission(file_id):
    """
    Handle permission requests for file access with organization context.
    """
    if 'user_email' not in session:
        flash('Please log in to request permissions.', 'warning')
        return redirect(url_for('auth.login'))

    try:
        user_email = session['user_email']
        
        # Get user details
        user = mongo.db.users.find_one({
            "email": user_email
        })
        
        if not user:
            flash('User details not found.', 'danger')
            return redirect(url_for('user.user_dashboard'))

        # Get organization details
        organization = mongo.db.organizations.find_one({
            "organization_id": user['organization_id'],
            "members": user_email  # Verify user is a member
        })

        if not organization:
            flash('Organization details not found or unauthorized access.', 'danger')
            return redirect(url_for('user.user_dashboard'))

        # Get file details
        file = mongo.db.files.find_one({'_id': ObjectId(file_id)})
        if not file:
            flash('File not found.', 'danger')
            return redirect(url_for('user.user_dashboard'))

        # Check if user already has a pending request for this file
        existing_request = mongo.db.requests.find_one({
            'file_id': ObjectId(file_id),
            'requested_by': user_email,
            'status': 'pending'
        })

        if existing_request:
            flash('You already have a pending request for this file.', 'warning')
            return redirect(url_for('user.user_dashboard'))

        # Get request details from form
        permission_type = request.form['permission_type']  # read/write
        purpose = request.form.get('purpose', '')  # Optional purpose field
        duration = request.form.get('duration', '24')  # Access duration in hours

        # Create the request
        request_data = {
            'file_id': ObjectId(file_id),
            'file_name': file['filename'],
            'requested_by': user_email,
            'requester_name': user['name'],
            'organization_id': organization['organization_id'],
            'admin_email': organization['admin_email'],
            'permission_type': permission_type,
            'purpose': purpose,
            'requested_duration': int(duration),
            'status': 'pending',
            'request_date': datetime.now(),
            'organization_name': organization['organization_name']
        }

        # Insert request
        mongo.db.requests.insert_one(request_data)

        # Send email notification to admin
       
         # Log the activity
        mongo.db.activity_logs.insert_one({
            'organization_id': organization['organization_id'],
            'action': 'permission_requested',
            'user_email': user_email,
            'file_id': file_id,
            'file_name': file['filename'],
            'permission_type': permission_type,
            'timestamp': datetime.now()
        })

        flash('Permission request submitted successfully! You will receive an email when it is processed.', 'success')

    except Exception as e:
        flash(f'Error submitting request: {str(e)}', 'danger')

    return redirect(url_for('user.user_dashboard'))

@bp.route('/access-file_page', methods=['GET'])
def access_file_page():
    return render_template('access_file.html')



@bp.route('/upload_file', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            flash('No file uploaded.', 'danger')
            return redirect(url_for('user.user_dashboard'))

        file = request.files['file']
        if not file or file.filename.strip() == '':
            flash('No valid file selected.', 'danger')
            return redirect(url_for('user.user_dashboard'))

        filename = secure_filename(file.filename)
        file_ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ""

        # Ensure UPLOAD_FOLDER exists
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER)

        file_path = os.path.join(UPLOAD_FOLDER, filename)
        print(f"Saving file to: {file_path}")  # Debugging output

        file.save(file_path)

        # Convert file if necessary
        converted_path = convert_file(file_path, file_ext)
        file_to_encrypt = converted_path if converted_path else file_path

        # Encrypt the file
        uploaded_at = datetime.now()
        encrypted_data, encryption_key = encrypt_file(file_to_encrypt, filename, uploaded_at)

        if encrypted_data is None:
            flash("Error encrypting the file.", "danger")
            cleanup_files(file_path, converted_path)
            return redirect(url_for('user.user_dashboard'))

        # Save to database
        uploaded_file = {
            'filename': filename if not converted_path else os.path.basename(converted_path),
            'encryption_key': encryption_key,
            'encrypted_data': encrypted_data,
            'organization_id': session.get('organization_id'),
            'uploaded_at': uploaded_at,
            'uploaded_by': session.get('user_email')
        }

        mongo.db.activity_logs.insert_one({
            'organization_id': session.get('organization_id'),
            'user_email': session.get('user_email'),
            'file_name': filename if not converted_path else os.path.basename(converted_path),
            'action': 'file_uploaded',
            'timestamp': uploaded_at,
        })

        result = mongo.db.files.insert_one(uploaded_file)

        # Cleanup
        cleanup_files(file_path, converted_path)

        if result.inserted_id:
            flash('File uploaded, converted (if needed), encrypted, and stored successfully!', 'success')
        else:
            flash('Failed to save the file in the database.', 'danger')

    except Exception as e:
        print(f"Error during file upload: {e}")
        flash(f"An error occurred: {str(e)}", 'danger')

    return redirect(url_for('user.user_dashboard'))



@bp.route('/stored_files', methods=['GET'])
def stored_files():
   
    user_email = session.get('user_email')

    if not user_email:
        return render_template('error.html', message="Please log in to view your stored files.")

    files = mongo.db.files.find({'uploaded_by': user_email})
    return render_template('stored_files.html', files=files)

@bp.route('/settings', methods=['GET'])
def permission():
    user_email = session.get('user_email')
    if not user_email:
        return render_template('error.html', message="Please log in to access settings.")

    return render_template('permission.html')

@bp.route('/access_file', methods=['POST'])
def access_file():
    qr_code_file = request.files.get('qr_code_file')

    if not qr_code_file:
        flash('QR code file is required.', 'danger')
        return redirect(url_for('user.access_file_page'))

    try:
        # Save the uploaded QR code image temporarily
        temp_file_path = "temp_qr_code.png"
        qr_code_file.save(temp_file_path)

        # Read and decode QR code
        img = cv2.imread(temp_file_path)
        if img is None:
            flash('Invalid image file.', 'danger')
            return redirect(url_for('user.access_file_page'))

        # Convert image to grayscale for better QR detection
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Initialize QR code detector
        qr_code_detector = cv2.QRCodeDetector()
        decoded_data, points, _ = qr_code_detector.detectAndDecode(gray)

        if not decoded_data:
            flash('Unable to decode the QR code.', 'danger')
            return redirect(url_for('user.access_file_page'))

        # Parse the JSON data from QR code
        try:
            data_dict = json.loads(decoded_data)
            request_id = data_dict['request_id']
            decryption_key = data_dict['decryption_key']
        except json.JSONDecodeError:
            flash('Invalid QR code format.', 'danger')
            return redirect(url_for('user.access_file_page'))

        # Clean up temporary file
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

        # Validate request and file
        user_request = mongo.db.requests.find_one({'_id': ObjectId(request_id)})
        if not user_request:
            flash('Invalid request ID.', 'danger')
            return redirect(url_for('user.access_file_page'))

        # Check QR expiry
        if user_request.get('qr_expiry') and datetime.now() > user_request['qr_expiry']:
            flash('The QR code has expired.', 'danger')
            return redirect(url_for('user.access_file_page'))

        # Get file metadata
        file_meta = mongo.db.files.find_one({'filename': user_request['file_name']})
        if not file_meta:
            flash('File not found.', 'danger')
            return redirect(url_for('user.access_file_page'))

        # Verify decryption key
        if decryption_key != file_meta.get('encryption_key'):
            flash('Invalid decryption key.', 'danger')
            return redirect(url_for('user.access_file_page'))

        mongo.db.activity_logs.insert_one({
            'organization_id': session.get('organization_id'),
            'user_email': session.get('user_email'),
            'file_name': file_meta['filename'],
            'action': 'file_accessed',
            'timestamp': datetime.now(),
        })
        # Process the file based on permission type
        return process_file_access(user_request, file_meta, decryption_key)

    except Exception as e:
        flash(f'Error processing request: {str(e)}', 'danger')
        return redirect(url_for('user.access_file_page'))
    
@bp.route('/preview/<file_id>', methods=['GET'])
def preview_file(file_id):
    """Fetches the encrypted PDF, decrypts it, and serves it securely."""
    
    if 'user_email' not in session:
        return "Unauthorized", 401

    file_meta = mongo.db.files.find_one({'_id': ObjectId(file_id)})

    if not file_meta:
        return "File not found", 404

    try:
        encryption_key = file_meta.get('encryption_key').encode()
        fernet = Fernet(encryption_key)
        decrypted_data = fernet.decrypt(file_meta['encrypted_files']['pdf'].encode())

        return Response(decrypted_data, mimetype="application/pdf", headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'none'; object-src 'none'; frame-ancestors 'none';",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store, must-revalidate",
            "Pragma": "no-cache",
            "Permissions-Policy": "fullscreen=(), display-capture=()",
            "Content-Disposition": f"inline; filename={file_meta['original_filename']}.pdf"
        })

    except Exception as e:
        return f"Error decrypting file: {str(e)}", 500
