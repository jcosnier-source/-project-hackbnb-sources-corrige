import os
import re
import stripe

# Format officiel des identifiants de session Stripe Checkout.
# Documentation : https://docs.stripe.com/api/checkout/sessions/object
_CHECKOUT_SESSION_ID_RE = re.compile(r"^cs_(test|live)_[A-Za-z0-9]+$")


def create_checkout(reference, name, unit_price, quantity, confirmation_secret):
    """
        Create Stripe checkout
        Documentation: https://docs.stripe.com/checkout/quickstart?client=react&lang=python
    """
    
    stripe.api_key = os.getenv('STRIPE_API_KEY')
    origin_host = os.getenv('APP_ORIGIN_HOST')
    return stripe.checkout.Session.create(
        mode='payment',
        success_url=f"{origin_host}/booking/{reference}?checkout_confirmation_secret={confirmation_secret}",
        cancel_url=origin_host,
        line_items=[
            {
                'quantity': quantity,
                'price_data': {
                    'currency': 'EUR',
                    'unit_amount': round(unit_price * 100),
                    'product_data': {
                        'name': name,
                    },
                },
            },
        ],
    )

def get_checkout_lines(checkout_session_id):
    """
    CORRECTIF D3 (SSRF) :
    l'ancienne implémentation construisait l'URL de l'API Stripe par
    concaténation directe de `checkout_session_id` (`f"...sessions/{id}/line_items"`),
    authentifiée avec la clé secrète du serveur. Un attaquant pouvait
    injecter un chemin de traversal (ex: `../../customers#`) pour pivoter
    vers n'importe quel endpoint de l'API Stripe avec les pleins pouvoirs
    du serveur (confirmé : exfiltration de 624 clients et de leurs moyens
    de paiement via `../../customers/{id}/payment_methods`).

    Deux garde-fous indépendants sont appliqués :
    1. Le format de l'identifiant est strictement validé AVANT tout appel
       (un identifiant Stripe valide ne peut jamais contenir '/', '.', '#').
    2. L'appel passe par le SDK officiel `stripe`, qui cible l'API par
       paramètre et non par concaténation d'URL : aucune valeur ne peut
       altérer le chemin de la requête HTTP sortante.
    """

    if not checkout_session_id or not _CHECKOUT_SESSION_ID_RE.match(checkout_session_id):
        raise ValueError("Invalid Stripe checkout session ID format")

    stripe.api_key = os.getenv('STRIPE_API_KEY')
    line_items = stripe.checkout.Session.list_line_items(checkout_session_id)
    return line_items["data"]
