import base64
from datetime import datetime, timedelta
from sqlite3 import IntegrityError
import uuid
import logging
from flask import Blueprint, jsonify, request, session
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token, 
    jwt_required, 
    current_user,
    get_jwt,
    get_jwt_identity
)
from extensions import db
from crypto_utils import encrypt_private_key, generate_encryption_key, generate_keys, load_and_decrypt_private_key
from models import User, TokenBlocklist
from cryptography.hazmat.primitives import serialization

# Création d'un Blueprint pour l'authentification
auth_bp = Blueprint('auth', __name__)

@auth_bp.post('/register')
def register_user():
    """Enregistre un nouvel utilisateur."""
    data = request.get_json()

    # Vérification des champs requis
    required_fields = ['username', 'email', 'password']
    if not data or not all(key in data for key in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    # Vérification des saisies vides
    for field in required_fields:
        if not data[field] or data[field].strip() == "":
            return jsonify({"error": f"{field} cannot be empty"}), 400

    try:
        # Vérification de l'existence de l'utilisateur par son email
        existing_user = User.query.filter((User.email == data['email'])).first()
        if existing_user:
            return jsonify({"error": "Email already exists"}), 409

        # Génération des clés et du sel pour l'encryption
        private_key_pem, public_key_pem = generate_keys()
        encryption_key, salt = generate_encryption_key(data['password'])
        encrypted_private_key = encrypt_private_key(encryption_key, private_key_pem)

        """# Logs pour le sel et la clé privée
        logging.debug(f'Generated salt: {base64.b64encode(salt).decode("utf-8")}')
        logging.debug(f'Encrypted private key: {base64.b64encode(encrypted_private_key).decode("utf-8")}')
"""
        # Création d'un nouvel utilisateur avec le rôle staff si spécifié
        is_staff = data.get('is_staff', False)  # Par défaut, is_staff est False
        new_user = User(
            id=str(uuid.uuid4()),
            username=data['username'],
            email=data['email'],
            public_key=public_key_pem.decode('utf-8'),
            private_key=base64.b64encode(encrypted_private_key).decode('utf-8'),
            salt=base64.b64encode(salt).decode('utf-8'),
            is_staff=is_staff  # Ajout du champ is_staff
        )
        new_user.set_password(data['password'])
        new_user.save()

        return jsonify({"message": "User created"}), 201

    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Email already exists"}), 409
    except Exception as e:
        #logging.error(f"Error during user registration: {str(e)}")
        return jsonify({"error": str(e)}), 500
    
@auth_bp.post('/login')
def login_user():
    """Authentifie un utilisateur et génère des tokens d'accès."""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Vérification des informations d'identification
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    # Recherche de l'utilisateur par email
    user = User.query.filter_by(email=email).one_or_none()

    # Vérification de l'existence de l'utilisateur et de la validité du mot de passe
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid email or password"}), 401

    encrypted_private_key = user.private_key
    salt = user.salt

    # Ajout de logs pour le sel
    logging.debug(f'Salt before decoding: {salt}')

    try:
        # Déchiffrement de la clé privée
        private_key = load_and_decrypt_private_key(encrypted_private_key, password, salt)
        # Stockage de la clé privée déchiffrée en session
        session['private_key'] = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
        session['private_key_expiry'] = (datetime.utcnow() + timedelta(hours=10)).isoformat()
            
        session['user_id'] = user.id
        session.permanent = True  # Rendre la session permanente
            
    except Exception as e:
        #logging.error(f"Error decrypting private key: {str(e)}")
        return jsonify({"error": "Failed to decrypt private key"}), 500

    if user.is_staff_member():
        logging.info(f"User {user.username} is a staff member.")

    # Création des tokens d'accès et de rafraîchissement
    access_token = create_access_token(identity=user.email)
    refresh_token = create_refresh_token(identity=user.email)

    return jsonify(
        {
            "message": "Logged In",
            "token": {
                "access": access_token,
                "refresh": refresh_token
            }
        }
    ), 200

@auth_bp.get('/whoami')
@jwt_required()
def whoami():
    """Renvoie les détails de l'utilisateur connecté."""
    return jsonify(
        {
            "message": "message",
            "user_details": {
                "username": current_user.username, 
                "email": current_user.email
            }
        }
    )

@auth_bp.get('/refresh')
@jwt_required(refresh=True)
def refresh_access():
    """Rafraîchit le token d'accès."""
    identity = get_jwt_identity()
    
    new_access_token = create_access_token(identity=identity)

    return jsonify({"access_token": new_access_token}), 200

@auth_bp.get('/logout')
@jwt_required(verify_type=False)
def logout_user():
    """Déconnecte l'utilisateur en révoquant le token."""
    jwt = get_jwt()
    jti = jwt['jti']  # Identifiant du token
    token_type = jwt['type']

    # Ajout à la liste de blocage des tokens
    token_b = TokenBlocklist(jti=jti)
    token_b.save()

    # Effacer les informations sensibles de la session
    session.pop('private_key', None)
    session.pop('user_id', None)
    session.pop('private_key_expiry', None)

    return jsonify({"message": f"{token_type} token revoked successfully and user deconnected"}), 200