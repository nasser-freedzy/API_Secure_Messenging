#####################################################################################################################################

# API de Messagerie Sécurisée

## Aperçu

L'API de Messagerie Sécurisée est une application basée sur Flask qui permet aux utilisateurs d'envoyer et de recevoir des messages et des fichiers chiffrés. Elle utilise des JWT (JSON Web Tokens) pour l'authentification et des techniques de cryptographie pour garantir la confidentialité et l'intégrité des communications des utilisateurs.

## Fonctionnalités

- **Authentification des Utilisateurs** : Les utilisateurs peuvent s’inscrire, se connecter et gérer leurs sessions de manière sécurisée.
- **Envoi de Messages** : Les utilisateurs peuvent envoyer des messages texte et des fichiers à d'autres utilisateurs.
- **Chiffrement des Messages** : Tous les messages sont chiffrés à l'aide de la cryptographie à clé publique, garantissant que seul le destinataire prévu peut les lire.
- **Téléversement de Fichiers** : Les utilisateurs peuvent téléverser des fichiers de manière sécurisée, en parallèle des messages texte.
- **Réception de Messages** : Les utilisateurs peuvent récupérer leurs messages, avec déchiffrement et vérification des signatures.
- **Authentification JWT** : Sécurisez les sessions utilisateur à l'aide de JSON Web Tokens.

## Mise en Route

### Prérequis

- Python 3.6+
- Flask
- Flask-SQLAlchemy
- Flask-JWT-Extended
- Cryptography
- Marshmallow
- Python-dotenv

### Installation

1. Créez un environnement virtuel :
   ```bash
   python -m venv venv
   source venv/bin/activate  # Sur Windows, utilisez `venv\Scripts\activate`
   ```

2. Installez les paquets requis :
   ```bash
   pip install -r requirements.txt
   ```

3. Créez un fichier `.env` dans le répertoire racine avec le contenu suivant :
   ```env
   FLASK_SECRET_KEY=your_secret_key
   FLASK_SQLALCHEMY_DATABASE_URI=sqlite:///db.sqlite3
   FLASK_JWT_SECRET_KEY=your_jwt_secret_key
   FLASK_DEBUG=True
   ```

### Exécution de l'API

1. Définissez la variable d'environnement Flask :
   ```bash
   export FLASK_APP=main.py
   export FLASK_ENV=development  # Pour l'environnement de développement
   ```

2. Exécutez l'application :
   ```bash
   flask run
   ```

### Points de Terminaison de l'API

- **Authentification** :
  - `POST /auth/register` : Inscrire un nouvel utilisateur.
  - `POST /auth/login` : Se connecter en tant qu'utilisateur existant.
  - `GET /auth/logout` : Se déconnecter de l'utilisateur actuel.

- **Gestion des Utilisateurs** :
  - `GET /users/<user_id>` : Récupérer les informations d'un utilisateur.

- **Messagerie** :
  - `POST /messaging/send_message` : Envoyer un message ou un fichier à un autre utilisateur.
  - `POST /messaging/receive_messages` : Récupérer les messages envoyés à l'utilisateur actuel.
  - `GET /messaging/download_file/<file_id>` : Télécharger un fichier associé à un message.

## Contribuer

Les contributions sont les bienvenues ! Veuillez soumettre une demande de tirage ou ouvrir une issue pour en discuter.


## Authentification API

Ce fichier `auth.py` définit les routes d'authentification pour une application Flask. Chaque fonction gère des aspects spécifiques de l'authentification des utilisateurs.

### Routes

#### 1. **POST /register**
- **Description**: Enregistre un nouvel utilisateur.
- **Paramètres requis**:
  - `username`: Nom d'utilisateur.
  - `email`: Adresse e-mail.
  - `password`: Mot de passe.
  - `is_staff` (optionnel): Indique si l'utilisateur est membre du personnel.
- **Réponses**:
  - `201 Created`: Utilisateur créé avec succès.
  - `400 Bad Request`: Champs requis manquants.
  - `409 Conflict`: L'utilisateur existe déjà.
  - `500 Internal Server Error`: Erreur lors de la création.

#### 2. **POST /login**
- **Description**: Authentifie un utilisateur et génère des tokens d'accès.
- **Paramètres requis**:
  - `email`: Adresse e-mail.
  - `password`: Mot de passe.
- **Réponses**:
  - `200 OK`: Connexion réussie, retourne les tokens d'accès.
  - `400 Bad Request`: Email et mot de passe requis.
  - `401 Unauthorized`: Identifiants invalides.
  - `500 Internal Server Error`: Échec de déchiffrement de la clé privée.

#### 3. **GET /whoami**
- **Description**: Renvoie les détails de l'utilisateur connecté.
- **Réponses**:
  - `200 OK`: Détails de l'utilisateur (nom d'utilisateur et email).
  - **Requiert**: Un token JWT valide.

#### 4. **GET /refresh**
- **Description**: Rafraîchit le token d'accès.
- **Réponses**:
  - `200 OK`: Nouveau token d'accès.
  - **Requiert**: Un token JWT de rafraîchissement valide.

#### 5. **GET /logout**
- **Description**: Déconnecte l'utilisateur en révoquant le token.
- **Réponses**:
  - `200 OK`: Message de confirmation de révocation.
  - **Requiert**: Un token JWT valide.

### Notes

- **Sécurité**: Toutes les routes sensibles nécessitent une authentification par JWT, garantissant que seules les requêtes autorisées peuvent accéder à certaines ressources.
- **Gestion des erreurs**: Des messages d'erreur détaillés sont fournis pour aider au débogage.

Ce fichier constitue la base de l'API d'authentification, permettant une gestion sécurisée des utilisateurs dans l'application.


## Utilisateurs API

Le fichier `users.py` définit les routes pour gérer les utilisateurs dans une application Flask. Cette API permet d'accéder à la liste des utilisateurs, mais seulement aux membres du personnel.

### Routes

#### 1. **GET /all**
- **Description**: Récupère tous les utilisateurs.
- **Sécurité**: Nécessite un token JWT valide. Seuls les utilisateurs avec le champ `is_staff` défini sur `True` peuvent accéder à cette route.
- **Paramètres optionnels**:
  - `page`: Numéro de la page à récupérer (par défaut: 1).
  - `per_page`: Nombre d'utilisateurs par page (par défaut: 3).
- **Réponses**:
  - `200 OK`: Retourne la liste des utilisateurs au format JSON.
  - `401 Unauthorized`: Message d'erreur si l'utilisateur n'est pas autorisé à accéder à cette ressource.

### Notes

- **Pagination**: La route utilise la pagination pour gérer les grandes listes d'utilisateurs, ce qui améliore la performance et l'expérience utilisateur.
- **Validation des rôles**: La vérification des rôles est cruciale pour la sécurité, garantissant que seuls les utilisateurs autorisés peuvent voir les informations sensibles.


## Messaging API

Le fichier `messaging.py` définit les routes pour gérer l'envoi et la réception de messages dans une application Flask. Cette API permet l'échange sécurisé de messages textuels et de fichiers entre utilisateurs.

### Routes

#### 1. **POST /send_message**
- **Description**: Envoie un message (texte ou fichier) d'un utilisateur à un autre.
- **Paramètres requis**:
  - `sender_email`: Email de l'expéditeur.
  - `receiver_email`: Email du destinataire.
  - `content_type`: Type de contenu (`text` ou `file`).
  - `text_content` (optionnel): Contenu texte du message.
  - `file` (optionnel): Fichier à envoyer.
- **Réponses**:
  - `200 OK`: Message envoyé avec succès.
  - `400 Bad Request`: Erreur de contenu ou d'adresse email.
  - `500 Internal Server Error`: Erreur lors du traitement.

#### 2. **POST /receive_messages**
- **Description**: Récupère les messages envoyés d'un utilisateur à un autre.
- **Paramètres requis**:
  - `sender_email`: Email de l'expéditeur.
  - `receiver_email`: Email du destinataire.
- **Réponses**:
  - `200 OK`: Liste des messages décryptés.
  - `400 Bad Request`: Erreur de contenu ou d'adresse email.
  - `404 Not Found`: Aucun message trouvé.
  - `500 Internal Server Error`: Erreur lors du traitement.

#### 3. **GET /download_file/<string:file_id>**
- **Description**: Télécharge un fichier envoyé dans un message.
- **Paramètres requis**:
  - `file_id`: Identifiant du message contenant le fichier.
- **Réponses**:
  - `200 OK`: Fichier téléchargé avec succès.
  - `404 Not Found`: Fichier introuvable ou type invalide.
  - `400 Bad Request`: Clé privée non trouvée en session.
  - `500 Internal Server Error`: Erreur lors du téléchargement.

### Notes

- **Sécurité**: Les messages sont chiffrés et signés pour garantir la confidentialité et l'intégrité. Les clés privées sont stockées en session.
- **Types de contenu**: Le système prend en charge les messages textuels et les fichiers (formats autorisés : `.txt`, `.pdf`, `.png`, `.jpg`, `.jpeg`, `.gif`).
- **Gestion des erreurs**: Des messages d'erreur clairs sont fournis pour faciliter le débogage et l'expérience utilisateur.

#####################################################################################################################################