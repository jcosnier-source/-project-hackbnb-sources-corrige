import hmac
import secrets
import string
from datetime import date
from flask import jsonify, Blueprint, request

from database.init import db
from api.rooms.rooms_models import Room
from services.stripe import create_checkout, get_checkout_lines
from .bookings_models import Booking
from sqlalchemy.orm import joinedload

bookings_api = Blueprint('bookings', __name__)


@bookings_api.route('/<reference>', methods=['GET'])
def get_booking_details(reference: str):
    """
    Get booking details
    """

    booking = Booking.query.options(joinedload(Booking.room)).filter_by(reference=reference).first()
    if not booking:
        return {'error': 'Booking not found'}, 404

    return jsonify(booking.to_dict())


@bookings_api.route('/<reference>/checkout-lines', methods=['GET'])
def get_booking_checkout_lines(reference: str):
    """
    Get booking checkout lines
    """

    booking = Booking.query.options(joinedload(Booking.room)).filter_by(reference=reference).first()
    if not booking:
        return {'error': 'Booking not found'}, 404
    
    if not booking.is_paid:
        return {'error': 'Cannot get checkout lines without payment'}, 422

    # CORRECTIF D3 (défense en profondeur) : l'ancien code acceptait
    # `checkout_session_id` depuis les paramètres de la requête cliente,
    # c'est CETTE valeur non authentifiée qui permettait le SSRF ci-dessus.
    # Le serveur connaît déjà l'identifiant de session associé à CETTE
    # réservation (booking.stripe_checkout_session_id) : il n'y a donc
    # aucune raison de faire confiance à une valeur fournie par le client.
    try:
        return jsonify(get_checkout_lines(booking.stripe_checkout_session_id))
    except (ValueError, Exception):
        return {'error': 'Invalid checkout session ID'}, 404


@bookings_api.route('/', methods=['POST'])
def new_booking():
    """
    Register a new booking for a room
    """

    # Check room exists
    room = Room.query.filter_by(id=request.json["roomId"]).first()
    if not room:
        return {'error': 'Room not found'}, 404

    # Check arrival date is format YYYY-MM-DD
    try:
        arrival_date = date.fromisoformat(request.json["arrivalDate"])
    except:
        return {'error': 'Invalid arrival date'}, 400

    # Check departure date is format YYYY-MM-DD
    try:
        departure_date = date.fromisoformat(request.json["departureDate"])
    except:
        return {'error': 'Invalid departure date'}, 400
    
    # Check departure date is later than arrival date
    if departure_date < arrival_date:
        return {'error': 'Invalid departure date'}, 400

    # Check guests count is valid and < 10 guests
    guests_count = request.json["guestsCount"]
    if not isinstance(guests_count, int) or guests_count < 1 or guests_count > 10:
        return {'error': 'Invalid guests count'}, 400
    
    # Determine how many days is the booking for
    booking_duration_in_days = (departure_date - arrival_date).days
    if booking_duration_in_days < 1:
        return {'error': 'Invalid booking duration'}, 400
    
    # Determine the booking total price
    booking_price = room.price * booking_duration_in_days

    # CORRECTIF complémentaire (repéré lors d'une revue croisée) : la référence
    # était elle aussi générée avec `random` (PRNG non cryptographique, Mersenne
    # Twister), pas `secrets`. Impact moindre que D4 (la référence n'est pas un
    # secret d'autorisation), mais il n'y a aucune raison de laisser une seconde
    # source d'aléa non sûre dans le même flux ; uniformisation sur `secrets`.
    booking_reference = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

    # CORRECTIF D4 (génération de secret faible) :
    # l'ancienne implémentation hashait le timestamp Unix courant (en
    # secondes) : la valeur était donc devinable en quelques centaines de
    # tentatives autour de l'heure de création de la réservation (brute
    # force observé dans les logs, 2 tentatives avant pivot vers le SQLi).
    # `secrets.token_hex` utilise le générateur cryptographiquement sûr du
    # système d'exploitation (CSPRNG) : la valeur n'est dérivable d'aucune
    # donnée connue ou devinable par un attaquant.
    checkout_confirmation_secret = secrets.token_hex(32)

    # Create Stripe checkout session
    checkout_session = create_checkout(
        reference=booking_reference,
        name=f"{booking_duration_in_days} nuit{'s' if booking_duration_in_days > 1 else ''} à {room.title} ({room.city})",
        unit_price=room.price,
        quantity=booking_duration_in_days,
        confirmation_secret=checkout_confirmation_secret,
    )

    # Create booking
    db.session.add(Booking(
        reference=booking_reference,
        arrival_date=request.json["arrivalDate"],
        departure_date=request.json["departureDate"],
        guests_count=guests_count,
        total_price=booking_price,
        checkout_confirmation_secret=checkout_confirmation_secret,
        stripe_checkout_session_id=checkout_session.id,
        is_paid=False,
        room_id=room.id,
    ))
    db.session.commit()

    return jsonify({
        "reference": booking_reference,
        "duration_in_days": booking_duration_in_days,
        "price": booking_price,
        "checkout_url": checkout_session.url,
    })


@bookings_api.route('/<reference>/confirm-checkout', methods=['POST'])
def confirm_booking_checkout(reference: str):
    """
    Confirm checkout payment for a booking
    """

    booking = Booking.query.filter_by(reference=reference).first()
    if not booking:
        return {'error': 'Booking not found'}, 404
    
    provided_secret = request.json.get("confirmationSecret", "")
    # Comparaison en temps constant (défense en profondeur contre le timing attack),
    # en complément du passage à un secret cryptographiquement sûr (cf. D4 ci-dessus).
    if not hmac.compare_digest(booking.checkout_confirmation_secret, provided_secret):
        return {'error': 'Invalid confirmation secret'}, 422

    booking.is_paid = True
    db.session.commit()

    return jsonify({
        "success": True,
    })
