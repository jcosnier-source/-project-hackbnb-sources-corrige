from flask import jsonify, Blueprint, request, send_from_directory
from sqlalchemy.orm import joinedload
from .rooms_models import Room
from database.init import db

rooms_api = Blueprint('rooms', __name__)


@rooms_api.route('/', methods=['GET'])
def list_rooms():
   """
   List all available rooms with given category
   """

   # CORRECTIF D1 (injection SQL - CVE interne) :
   # l'ancienne implémentation injectait `category` directement dans une
   # requête SQL brute via f-string (`text(f"category = '{category}'")`),
   # permettant une injection UNION-based (cf. annexe forensic : extraction
   # de bookings.checkout_confirmation_secret et de users.password_hash).
   # On utilise désormais le filtre ORM paramétré de SQLAlchemy, qui lie la
   # valeur via une requête préparée (paramètres bindés, jamais interpolés
   # dans le texte SQL).
   if "category" in request.args:
      category = request.args["category"]
      rooms = Room.query.filter_by(category=category).all()
   else:
      rooms = Room.query.all()

   return jsonify([room.to_dict() for room in rooms])


@rooms_api.route('/<room_id>', methods=['GET'])
def get_room_details(room_id: str):
   """
   Get room details
   """

   room = Room.query.options(joinedload(Room.host_user)).filter_by(id=room_id).first()
   if not room:
      return {'error': 'Room not found'}, 404

   return jsonify(room.to_dict())


@rooms_api.route('/<room_id>/picture')
def send_report(room_id: str):
   return send_from_directory('pictures', room_id + ".jpg")
