from extensions import db
from uuid import uuid4
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(), primary_key=True, default=lambda: str(uuid4()))
    username = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), nullable=False, unique=True)
    password = db.Column(db.Text(), nullable=False)
    public_key = db.Column(db.Text(), nullable=False)
    private_key = db.Column(db.Text(), nullable=False)
    salt = db.Column(db.Text(), nullable=False)
    is_staff = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<User {self.username}>"

    def set_password(self, password):
        """Hash le mot de passe et le stocke dans l'attribut password."""
        self.password = generate_password_hash(password)

    def check_password(self, password):
        """Vérifie si le mot de passe fourni correspond au mot de passe haché."""
        return check_password_hash(self.password, password)
    
    def is_staff_member(self):
        """Retourne True si l'utilisateur est un membre du personnel."""
        return self.is_staff 

    @classmethod
    def get_user_by_username(cls, username):
        """Récupère un utilisateur par son nom d'utilisateur."""
        return cls.query.filter_by(username=username).first()

    def save(self):
        """Sauvegarde l'utilisateur dans la base de données."""
        try:
            db.session.add(self)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e

    def delete(self):
        """Supprime l'utilisateur de la base de données."""
        try:
            db.session.delete(self)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e

class TokenBlocklist(db.Model):
    """Modèle pour gérer la liste noire des jetons."""
    id = db.Column(db.Integer(), primary_key=True)
    jti = db.Column(db.String(), nullable=True)  # Identifiant du jeton
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Token {self.jti}>"

    def save(self):
        """Sauvegarde le jeton dans la base de données."""
        db.session.add(self)
        db.session.commit()

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.String(), primary_key=True, default=lambda: str(uuid4()))
    sender_id = db.Column(db.String(), db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.String(), db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.LargeBinary, nullable=False)  # Contenu binaire du message
    content_hash = db.Column(db.String(), nullable=False)  # Hachage du contenu
    content_type = db.Column(db.String(), nullable=False)  # Type de contenu (texte, pdf, audio, vidéo)
    signature = db.Column(db.String, nullable=False)  # Signature du message
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

    def save(self):
        """Sauvegarde le message dans la base de données."""
        db.session.add(self)
        db.session.commit()