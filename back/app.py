import os
from flask import Flask
from flask_cors import CORS
from database.init import db
from database.seed import seed_database

from api.rooms.rooms_models import Room
from api.rooms.rooms_api import rooms_api
from api.users.users_models import User
from api.users.users_api import users_api
from api.auth.auth_api import auth_api
from api.bookings.bookings_api import bookings_api
from api.bookings.bookings_models import Booking
from api.uploads.uploads_api import uploads_api


app = Flask(__name__)
app.config.from_pyfile('config.py')

# Add CORS to all requests
CORS(app, origins=app.config["CORS_ORIGINS"])

# Initialize database
db.init_app(app)
with app.app_context():
   db.create_all()
   seed_database()

# Routes
app.register_blueprint(rooms_api, url_prefix='/rooms')
app.register_blueprint(users_api, url_prefix='/users')
app.register_blueprint(auth_api, url_prefix='/auth')
app.register_blueprint(bookings_api, url_prefix='/bookings')
app.register_blueprint(uploads_api, url_prefix='/uploads')


@app.route('/', methods=['GET'])
def welcome():
   return "Welcome on API"


@app.after_request
def set_security_headers(response):
   """
   CORRECTIF D7 (en-têtes de sécurité manquantes) :
   absence totale d'en-têtes de durcissement, constatée par le pentest et
   non vérifiable/infirmée par les logs Apache (qui ne consignent pas les
   en-têtes de réponse). Ajout des en-têtes standards recommandés OWASP :
   https://owasp.org/www-project-secure-headers/
   """
   response.headers["X-Content-Type-Options"] = "nosniff"
   response.headers["X-Frame-Options"] = "DENY"
   response.headers["Content-Security-Policy"] = "default-src 'self'"
   response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
   response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
   if not app.debug:
      response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
   # CORRECTIF D8 (divulgation d'informations sensibles dans les en-têtes) :
   # Flask/Werkzeug annoncent leur version dans l'en-tête Server par défaut.
   response.headers["Server"] = "hackbnb"
   return response


if __name__ == '__main__':
   # CORRECTIF D8 (ter, trouvé en testant réellement le correctif ci-dessus) :
   # en développement (serveur Werkzeug intégré), response.headers["Server"]
   # ne suffit PAS : Werkzeug écrit sa propre bannière "Server: Werkzeug/x.y
   # Python/x.y" au niveau HTTP (BaseHTTPRequestHandler), en plus de celle de
   # la réponse applicative — un test réel (curl -I) le montre clairement,
   # les deux en-têtes apparaissent. Il faut surcharger le serveur de
   # développement lui-même. En production, ce problème ne se pose pas si
   # l'on utilise un serveur WSGI dédié (gunicorn) plutôt que app.run().
   from werkzeug.serving import WSGIRequestHandler
   WSGIRequestHandler.server_version = "hackbnb"
   WSGIRequestHandler.sys_version = ""

   # CORRECTIF D8 (bis) : `debug=True` était actif en production, exposant
   # le débogueur interactif Werkzeug (risque d'exécution de code arbitraire
   # si la route est atteignable) et des traces d'erreur détaillées
   # (stack trace, extraits de code source, variables d'environnement).
   # Le mode debug doit être explicitement activé par variable d'environnement
   # en développement uniquement, jamais par défaut.
   app.run(
      debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
      host="0.0.0.0",
      port=9001,
   )
