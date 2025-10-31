from flask import session

SUPPORTED_LANGUAGES = ["ru", "en"]
DEFAULT_LANGUAGE = "ru"


def get_current_language() -> str:
    language = session.get("language")
    if language in SUPPORTED_LANGUAGES:
        return language
    return DEFAULT_LANGUAGE


def set_language(language: str) -> None:
    if language in SUPPORTED_LANGUAGES:
        session["language"] = language
    else:
        session["language"] = DEFAULT_LANGUAGE
