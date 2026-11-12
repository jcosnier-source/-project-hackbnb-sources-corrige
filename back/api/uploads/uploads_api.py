import os
from flask import Blueprint, request, send_from_directory, abort

uploads_api = Blueprint('uploads', __name__)

# Dossier racine des uploads, résolu en chemin absolu une seule fois.
UPLOADS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'uploads'))


@uploads_api.route('/')
def get_upload():
   """
   CORRECTIF D2 (path traversal) :
   l'ancienne implémentation concaténait directement `name` à un chemin
   relatif ('uploads/' + name) et le passait à send_file, permettant de
   sortir du dossier uploads via `../` ou un chemin absolu (ex: /etc/passwd,
   .env — tentatives observées dans les logs Apache du 2 novembre).

   send_from_directory() de Flask/Werkzeug rejette nativement les chemins
   absolus et toute tentative de remontée (..), en plus de vérifier que le
   fichier résolu reste bien à l'intérieur de `UPLOADS_DIR`. On ajoute une
   whitelist d'extensions pour limiter la surface aux seules images.
   """

   name = request.args.get("name")
   if not name:
      abort(400, description="Missing 'name' parameter")

   allowed_extensions = {'.jpg', '.jpeg', '.png', '.webp'}
   _, ext = os.path.splitext(name)
   if ext.lower() not in allowed_extensions:
      abort(400, description="Invalid file type")

   try:
      return send_from_directory(UPLOADS_DIR, name)
   except (FileNotFoundError, PermissionError, NotADirectoryError):
      abort(404)
