import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, current_app
)
from werkzeug.security import check_password_hash, generate_password_hash

from server.db import get_db

from uuid_extensions import uuid7, uuid7str
import secrets
import duckdb
import base64

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialHint,
    ResidentKeyRequirement,
)

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route("/reset/register", methods=["GET"])
def reset():
    """
    Endpoint for an easy way to reset the database.
    This is a test application and would obviously
    be stupid in production!
    """
    con = get_db()
    con.sql("DELETE FROM register;")

    return {}

@bp.route("/register/begin", methods=["POST"])
def register_begin():
    if request.method == "POST":
        username = request.json.get("username", None)
        
        if not username:
            return { "type": "error", "msg": "username missing" }

        con = get_db()

        uid = secrets.token_bytes(64)
        challenge = secrets.token_bytes(32)
        
        try:
            con.execute("INSERT INTO register VALUES (?, ?, ?)", [
                uid, challenge, username 
            ])
        except duckdb.Error as error:
            return { "type": "error", "msg": f"{str(error)}" } 

        registration_options = generate_registration_options(
            rp_id=current_app.config['RP_ID'],
            rp_name=current_app.config['RP_NAME'],
            user_name=username,
            user_id=uid,
            challenge=challenge
        )

        return options_to_json(registration_options)


@bp.route("/register/complete", methods=["POST"])
def register_complete():
    return {}
