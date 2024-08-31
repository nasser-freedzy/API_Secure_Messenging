from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

# Initialisation de l'extension SQLAlchemy pour la gestion de la base de données
db = SQLAlchemy()

# Initialisation de l'extension JWT pour la gestion des tokens JWT
jwt = JWTManager()