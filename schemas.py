from marshmallow import fields, Schema

class UserSchema(Schema):
    """Schéma de validation et de sérialisation pour les utilisateurs."""
    id = fields.String()  # Identifiant unique de l'utilisateur
    username = fields.String()  # Nom d'utilisateur
    email = fields.String()  # Adresse email de l'utilisateur

class MessageSchema(Schema):
    """Schéma de validation et de sérialisation pour les messages."""
    id = fields.Int(dump_only=True)  # Identifiant unique du message (uniquement en sortie)
    sender_id = fields.Int(required=True)  # Identifiant de l'expéditeur (requis)
    receiver_id = fields.Int(required=True)  # Identifiant du destinataire (requis)
    encrypted_message = fields.Str(required=True)  # Message chiffré (requis)
    timestamp = fields.DateTime(dump_only=True)  # Horodatage du message (uniquement en sortie)