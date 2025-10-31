from __future__ import annotations

from flask import Flask
from flask_login import LoginManager

from .config import Config
from .language import SUPPORTED_LANGUAGES, get_current_language
from .models import User, db
from .translations import LANGUAGE_NAMES, get_translation_bundle, translate

login_manager = LoginManager()
login_manager.login_view = "main.login"


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)

    from .routes import bp as main_blueprint

    app.register_blueprint(main_blueprint)

    @login_manager.user_loader
    def load_user(user_id: str) -> User | None:  # pragma: no cover - callback
        if not user_id:
            return None
        return User.query.get(int(user_id))

    @app.context_processor
    def inject_translations():  # pragma: no cover - template helper
        language = get_current_language()
        bundle = get_translation_bundle(language)
        return {
            "t": lambda key, **kwargs: translate(key, language).format(**kwargs),
            "translations": bundle,
            "current_language": language,
            "language_choices": [(code, LANGUAGE_NAMES[code]) for code in SUPPORTED_LANGUAGES],
        }

    with app.app_context():
        db.create_all()

    return app
