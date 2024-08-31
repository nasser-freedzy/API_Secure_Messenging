from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt
from models import User
from schemas import UserSchema

# Création d'un Blueprint pour la gestion des utilisateurs
user_bp = Blueprint('users', __name__)

@user_bp.get('/all')
@jwt_required() 
def get_all_users():
    """Récupère tous les utilisateurs pour les membres du personnel."""
    
    # Récupération des claims du token JWT
    claims = get_jwt()
    
    # Vérification si l'utilisateur est un membre du personnel
    if claims.get('is_staff') == True:
        page = request.args.get('page', default=1, type=int)  # Numéro de la page
        per_page = request.args.get('per_page', default=3, type=int)  # Nombre d'utilisateurs par page
        
        # Récupération des utilisateurs avec pagination
        users = User.query.paginate(page=page, per_page=per_page)

        # Sérialisation des utilisateurs
        result = UserSchema().dump(users, many=True)

        return jsonify(
            {
                "users": result,
            }
        ), 200  # Retourne la liste des utilisateurs
    
    # Si l'utilisateur n'est pas autorisé
    return jsonify({"message": "You are not authorized to access this"}), 401