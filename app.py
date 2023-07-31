import os
from flask import Flask, jsonify
from flask_smorest import Api
from  flask_jwt_extended import JWTManager
from resources.item import  blp as ItemBlueprint
from resources.store import  blp as StoreBlueprint
from resources.tag import  blp as TagBlueprint
from resources.user import  blp as UserBlueprint
from db import db
import models
from blocklist import BLOCKLIST

def create_app(db_url = None):
    app = configure_flask_app()
    configure_sqlalchemy(app, db_url)
    configure_api(app)
    configure_jwt(app)
    return app

def configure_flask_app():
    app = Flask(__name__)
    app.config["PROPAGATE_EXCEPTIONS"] = True
    app.config["API_TITLE"] = "Stores REST API"
    app.config["API_VERSION"] = "v1"
    app.config["OPENAPI_VERSION"] = "3.0.3"
    app.config["OPENAPI_URL_PREFIX"] = "/"
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
    app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"
    
    return app

def configure_sqlalchemy(app, db_url):
    app.config["SQLALCHEMY_DATABASE_URI"] = db_url or os.getenv("DATABASE_URL", "sqlite:///data.db")
    db.init_app(app)
    with app.app_context():
        db.create_all()
        
def configure_api(app):
    api = Api(app)
    api.register_blueprint(ItemBlueprint)
    api.register_blueprint(StoreBlueprint)
    api.register_blueprint(TagBlueprint)
    api.register_blueprint(UserBlueprint)
    
def configure_jwt(app):
    app.config["JWT_SECRET_KEY"] = "ooops"
    jwt = JWTManager(app)
    
    @jwt.token_in_blocklist_loader
    def check_if_tocken_in_blocklist(jwt_header, jwt_payload):
        return jwt_payload["jti"] in BLOCKLIST
    
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return (
            jsonify({"message": "The token has been revoked.", "error": "token_revoked"}),
            401,
        )

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return (
            jsonify({"message": "The token has expired.", "error": "token_expired"}),
            401,
        )

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return (
            jsonify(
                {"message": "Signature verification failed.", "error": "invalid_token"}
            ),
            401,
        )

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return (
            jsonify(
                {
                    "description": "Request does not contain an access token.",
                    "error": "authorization_required",
                }
            ),
            401,
        )
