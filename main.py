import logging
from flask import Flask, jsonify
from crypto_utils import generate_symmetric_key
from extensions import db, jwt
from auth import auth_bp
from users import user_bp
from models import User, TokenBlocklist
from messaging import msg_bp


def create_app():
    """Crée et configure l'application Flask."""
    
    app = Flask(__name__)
    app.config.from_prefixed_env()  # Charge la configuration à partir des variables d'environnement
    app.secret_key = generate_symmetric_key()

    # Initialisation des extensions
    db.init_app(app)
    jwt.init_app(app)

    # Enregistrement des blueprints
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(user_bp, url_prefix="/users")
    app.register_blueprint(msg_bp, url_prefix="/messaging")

    # Chargement de l'utilisateur pour le JWT
    @jwt.user_lookup_loader
    def user_lookup_callback(jwt_header, jwt_data):
        """Récupère l'utilisateur en fonction de l'email stocké dans le token JWT."""
        identity = jwt_data['sub']
        logging.debug(f"Looking up user with email: {identity}")
        user = User.query.filter_by(email=identity).one_or_none()
        if user is None:
            logging.error(f"User not found: {identity}")
            raise Exception(f"User not found: {identity}")
        return user
    
    # Chargement des claims supplémentaires
    @jwt.additional_claims_loader
    def make_additional_claims(identity):
        """Ajoute des claims supplémentaires au token JWT."""
        user = User.query.filter_by(email=identity).one_or_none()
        if user and user.is_staff:
            return {"is_staff": True}
        return {"is_staff": False}

    # Gestionnaires d'erreurs pour le JWT
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_data):
        """Gère les tokens expirés."""
        return jsonify({"message": "Token has expired", "error": "token_expired"}), 401
        
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        """Gère les tokens invalides."""
        return (
            jsonify(
                {
                    "message": "Signature verification failed", "error": "invalid_token"
                }
            ), 401
        )
        
    @jwt.unauthorized_loader    
    def missing_token_callback(error):
        """Gère les requêtes sans token."""
        return (
            jsonify(
                {
                    "message": "Request does not contain valid token", "error": "authorization_header"
                }
            ), 401
        )

    @jwt.token_in_blocklist_loader
    def token_in_blocklist_callback(jwt_header, jwt_data):
        """Vérifie si le token est dans la liste de blocage."""
        jti = jwt_data['jti']
        token = db.session.query(TokenBlocklist).filter(TokenBlocklist.jti == jti).scalar()
        return token is not None 
    
    return app