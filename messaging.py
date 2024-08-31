import base64
from datetime import datetime
from io import BytesIO
import logging
from flask import Blueprint, jsonify, request, send_file, session
from crypto_utils import (
    encrypt_message,
    decrypt_message,
    hash_message,
    load_private_key,
    load_public_key,
    sign_message,
    verify_signature,
)
from models import Message, User
from extensions import db

# Création d'un Blueprint pour la gestion des messages
msg_bp = Blueprint('messaging', __name__)
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'epub', 'md', 'mp3', 'mp4'}

def allowed_file(filename):
    """Vérifie si le fichier a une extension autorisée."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# -------------------------------------------------
# Fonctions pour l'envoi de messages
# -------------------------------------------------

@msg_bp.post('/send_message')
def send_message():
    """Envoie un message (texte ou fichier) d'un utilisateur à un autre."""
    receiver_email = request.form.get('receiver_email')
    content_type = request.form.get('content_type')
    text_content = request.form.get('text_content')
    file = request.files.get('file')

    # Vérification de l'identification de l'utilisateur
    sender_id = session.get('user_id')

    logging.debug(f'Session ID: {session.get("user_id")}')
    if not sender_id:
        return jsonify({'error': 'User not logged in'}), 401

    # Récupération de l'utilisateur
    sender = User.query.get(sender_id)
    receiver = User.query.filter_by(email=receiver_email).first()

    if not sender or not receiver:
        return jsonify({'error': 'Invalid sender or receiver email'}), 400

    private_key_pem = session.get('private_key')
    if not private_key_pem:
        return jsonify({'error': 'Private key not found in session'}), 400

    try:
        private_key = load_private_key(private_key_pem)
        public_key = load_public_key(receiver.public_key)

        if content_type == 'text' and text_content:
            return handle_text_message(sender, receiver, text_content, public_key, private_key)

        if file and allowed_file(file.filename):
            return handle_file_message(sender, receiver, file, public_key, private_key)

        return jsonify({'error': 'Invalid content type or missing content'}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def handle_text_message(sender, receiver, text_content, public_key, private_key):
    """Gère l'envoi d'un message texte."""
    encrypted_content = encrypt_message(public_key, text_content.encode('utf-8'))
    content_hash = hash_message(text_content.encode('utf-8'))
    signature = sign_message(private_key, text_content)
    
    new_message = Message(
        sender_id=sender.id,
        receiver_id=receiver.id,
        content=encrypted_content,
        content_hash=content_hash,
        content_type='text',
        signature=signature
    )
    db.session.add(new_message)
    db.session.commit()

    return jsonify({'message': 'Message sent successfully'}), 200

def handle_file_message(sender, receiver, file, public_key, private_key):
    """Gère l'envoi d'un fichier."""
    content = file.read()
    encrypted_content = encrypt_message(public_key, content)
    content_hash = hash_message(content)
    signature = sign_message(private_key, content)    

    new_message = Message(
        sender_id=sender.id,
        receiver_id=receiver.id,
        content=encrypted_content,
        content_hash=content_hash,
        content_type='file',
        signature=signature
    )
    db.session.add(new_message)
    db.session.commit()

    return jsonify({'message': 'File sent successfully'}), 200

# -------------------------------------------------
# Fonctions pour la réception de messages
# -------------------------------------------------

@msg_bp.post('/receive_messages')
def receive_messages():
    """Récupère les messages envoyés d'un utilisateur à un autre."""
    receiver_id = session.get('user_id')
    if not receiver_id:
        return jsonify({'error': 'User not logged in'}), 401

    sender_email = request.form.get('sender_email')
    sender = User.query.filter_by(email=sender_email).first()
    receiver = User.query.get(receiver_id)

    if not sender or not receiver:
        return jsonify({'error': 'Invalid sender or receiver email'}), 400

    messages = Message.query.filter_by(sender_id=sender.id, receiver_id=receiver.id).all()
    if not messages:
        return jsonify({'error': 'No messages found'}), 404

    return jsonify({'messages': decrypt_messages(messages, sender)}), 200

def decrypt_messages(messages, sender):
    """Déchiffre les messages récupérés et vérifie les signatures."""
    decrypted_messages = []
    private_key_pem = session.get('private_key')
    if not private_key_pem:
        return jsonify({'error': 'Private key not found in session'}), 400

    # Chargement de la clé privée
    private_key = load_private_key(private_key_pem)

    for message in messages:
        if message.content_type == 'text':
            # Déchiffrement du message
            decrypted_message = decrypt_message(private_key, message.content)
            if not decrypted_message:
                continue
            
            content = decrypted_message.decode('utf-8')

            # Vérification du hash du message
            if hash_message(decrypted_message) != message.content_hash:
                continue  # Ignorer le message si le hash ne correspond pas

            # Vérification de la signature
            if not verify_signature_for_message(load_public_key(sender.public_key), content, message.signature):
                continue  # Ignorer le message si la signature est invalide

            decrypted_messages.append({
                'content': content,
                'content_type': message.content_type,
                'timestamp': message.timestamp.isoformat()
            })
        
        elif message.content_type == 'file':
            decrypted_messages.append({
                'file_id': message.id,
                'content_type': message.content_type,
                'timestamp': message.timestamp.isoformat()
            })

    return decrypted_messages

def verify_signature_for_message(public_key, content, signature):
    """Vérifie la signature d'un message."""
    try:
        signature_bytes = base64.b64decode(signature)
        return verify_signature(public_key, content, signature_bytes)
    except Exception as e:
        logging.error(f"Error verifying signature: {str(e)}")
        return False
    
# -------------------------------------------------
# Fonction de téléchargement de fichiers
# -------------------------------------------------

@msg_bp.get('/download_file/<string:file_id>')
def download_file(file_id):
    """Télécharge un fichier envoyé dans un message."""
    logging.debug(f'Requesting download for file ID: {file_id}')
    message = Message.query.filter_by(id=file_id).first()

    if not message or message.content_type != 'file':
        return jsonify({'error': 'File not found or invalid type'}), 404

    private_key_pem = session.get('private_key')
    if not private_key_pem:
        return jsonify({'error': 'Private key not found in session'}), 400

    try:
        private_key = load_private_key(private_key_pem)
        decrypted_content = decrypt_message(private_key, message.content)

        file_stream = BytesIO(decrypted_content)
        file_stream.seek(0)

        response = send_file(
            file_stream,
            download_name=f'file_{file_id}',
            as_attachment=True,
            mimetype='application/octet-stream'
        )

        response.headers['X-Message'] = 'File downloaded. You can open it with your preferred application.'
        return response

    except Exception as e:
        logging.error(f'Error downloading file: {str(e)}')
        return jsonify({'error': str(e)}), 500