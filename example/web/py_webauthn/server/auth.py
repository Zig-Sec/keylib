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

        print(f"\n[Begin Registration for {username}]")        

        con = get_db()

        # Check if a user with the given name already exists
        # This could be used to bruteforce usernames, i.e., should
        # at least be rate limited.

        con.execute("SELECT * from user WHERE username = ?", [username])
        r = con.fetchone()

        if r is not None:
            print(f"error: {username} does already exist")
            return { "type": "error", "msg": f"bad request" }, 500
    
        # Create data for a new credential registration

        uid = secrets.token_bytes(64)
        challenge = secrets.token_bytes(32)
        
        try:
            con.execute("INSERT INTO register VALUES (?, ?, ?)", [
                uid, challenge, username 
            ])
        except duckdb.Error as error:
            print(f"{str(error)}")
            return { "type": "error", "msg": f"bad request" }, 500

        registration_options = generate_registration_options(
            rp_id=current_app.config['RP_ID'],
            rp_name=current_app.config['RP_NAME'],
            user_name=username,
            user_id=uid,
            challenge=challenge,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
            ),
        )

        return options_to_json(registration_options)

@bp.route("/register/complete/<username>", methods=["POST"])
def register_complete(username):
    if request.method == "POST":
        print(f"\n[Complete Registration for {username}]")

        con = get_db()
        con.execute("SELECT * from register WHERE username = ?", [username])
        r = con.fetchone()
        print(f"fetch: {r}")
        
        delete_register_entry(con, r[0])

        if r is None:
            print("no such user")
            return {}

        response = request.json
        print("\n[Response from Client]")
        print(response)
        
        try:
            registration_verification = verify_registration_response(
                # The resposne is a json object as returned by 
                credential=response,
                expected_challenge=r[1],
                expected_origin="http://localhost:5000",
                expected_rp_id=current_app.config['RP_ID'],
                require_user_verification=True,
            )
        except e:
            print(f"\n[Verification Failed: {str(e)}]")
            return { "type": "error", "msg": f"{str(e)}" } 

        print("\n[Registration Verification]")
        print(registration_verification)
        print("\n[Credential ID]")
        print("".join("{:02x}".format(c) for c in registration_verification.credential_id))
        print("\n[Public Key]")
        print("".join("{:02x}".format(c) for c in registration_verification.credential_public_key))
        print("\n[Sign Count]")
        print(registration_verification.sign_count)

        try:
            con.execute("INSERT OR IGNORE INTO user VALUES (?, ?)", [
                r[0], username,
            ])
        except duckdb.Error as error:
            print(f"error: creating user failed  {str(error)}")
            return { "type": "error", "msg": f"bad request" }, 500

        try:
            con.execute("INSERT OR REPLACE INTO passkey VALUES (?, ?, ?, ?)", [
                registration_verification.credential_id,
                registration_verification.credential_public_key,
                registration_verification.sign_count,
                r[0],
            ])
        except duckdb.Error as error:
            print(f"error: registering passkey failed {str(error)}")
            return { "type": "error", "msg": f"bad request" }, 500

    return {}


@bp.route("begin/<username>", methods=["POST"])
def auth_begin(username):
    if request.method == "POST":
        print(f"\n[Begin Authentication for {username}]")

        con = get_db()
        con.execute("SELECT * from register WHERE username = ?", [username])
        r = con.fetchone()
        print(f"fetch: {r}")



def delete_register_entry(con, id):
    con.execute("DELETE FROM register WHERE id = ?;", [id])
