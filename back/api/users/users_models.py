from typing import List
from werkzeug.security import generate_password_hash, check_password_hash
from database.init import db
from sqlalchemy.orm import Mapped, mapped_column, relationship

class User(db.Model):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column()
    email: Mapped[str] = mapped_column(unique=True)
    password_hash: Mapped[str] = mapped_column()
    rooms: Mapped[List["Room"]] = relationship(back_populates="host_user")

    def __repr__(self):
        return f'<User {self.email!r}>'
    
    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
        }

    def to_public_dict(self):
        """
        CORRECTIF D5 (exposition de l'adresse e-mail des hôtes) :
        to_dict() (avec l'e-mail) ne doit être utilisé que pour le profil
        du compte lui-même (ex: après authentification). Toute exposition
        publique d'un utilisateur (ex: en tant qu'hôte d'une annonce,
        visible par n'importe quel visiteur non authentifié) doit passer
        par cette version restreinte.
        """
        return {
            "id": self.id,
            "name": self.name,
        }

    def set_password(self, clear_password: str):
        # CORRECTIF (constat complémentaire, hors D1-D8 du pentest, mais
        # directement lié à D1) : MD5 est un algorithme de hachage rapide
        # et non salé, cassable par rainbow table / brute force GPU en cas
        # d'exfiltration (la capture d'écran de l'équipe démontre que la
        # colonne password_hash est accessible via l'injection SQL D1).
        # werkzeug.security utilise scrypt (ou pbkdf2 selon la version),
        # salé individuellement par hash, avec un coût calculatoire élevé.
        self.password_hash = generate_password_hash(clear_password)

    def is_valid_password(self, clear_password: str) -> bool:
        return check_password_hash(self.password_hash, clear_password)
