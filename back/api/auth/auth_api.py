from flask import jsonify, Blueprint, request
from database.init import db
from api.users.users_models import User

auth_api = Blueprint('auth', __name__)


@auth_api.route('/login', methods=['POST'])
def login():
    if "email" not in request.json:
        return {'error': 'Missing email'}, 400
    if "password" not in request.json:
        return {'error': 'Missing password'}, 400

    # CORRECTIF (trouvé en testant réellement l'authentification, hors D1-D8) :
    # un compte inexistant renvoyait 404 "User not found" et un mauvais mot de
    # passe renvoyait 401 "Invalid password" — deux réponses distinctes qui
    # permettent d'énumérer les e-mails valides par essais successifs. Les
    # deux cas renvoient désormais exactement la même réponse.
    user: User = User.query.where(User.email == request.json["email"]).first()
    if not user or not user.is_valid_password(request.json["password"]):
        return {'error': 'Invalid email or password'}, 401

    return jsonify({})


@auth_api.route('/register', methods=['POST'])
def create_account():
    if "name" not in request.json:
        return {'error': 'Missing name'}, 400
    if "email" not in request.json:
        return {'error': 'Missing email'}, 400
    if "password" not in request.json:
        return {'error': 'Missing password'}, 400

    # Error if user already exists
    existing_user: User = User.query.where(User.email == request.json["email"]).first()
    if existing_user:
        return {'error': 'User with same email already exists'}, 409

    user = User(
        name=request.json["name"],
        email=request.json["email"],
    )

    user.set_password(request.json["password"])
    
    # Create user in database
    db.session.add(user)
    db.session.commit()

    return jsonify({})
