from __future__ import annotations

import json
from datetime import datetime
from typing import Dict

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

from .encryption import manager as encryption_manager
from .language import SUPPORTED_LANGUAGES, get_current_language, set_language
from .models import Test, TestQuestion, Theory, User, db
from .translations import translate

bp = Blueprint("main", __name__)


def _ensure_language():
    language = get_current_language()
    session["language"] = language
    return language


@bp.route("/")
def index():
    language = _ensure_language()
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return render_template("index.html", language=language)


@bp.route("/register", methods=["GET", "POST"])
def register():
    language = _ensure_language()
    algorithm_choices = encryption_manager.as_choices(language)
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        algorithm_id = request.form.get("algorithm")
        key_input = request.form.get("encryption_key") or None

        if password != confirm_password:
            flash(translate("password_mismatch", language))
            return render_template(
                "register.html",
                language=language,
                algorithms=algorithm_choices,
            )

        if not username or not password or not algorithm_id:
            flash(translate("invalid_credentials", language))
            return render_template(
                "register.html",
                language=language,
                algorithms=algorithm_choices,
            )

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash(translate("user_exists", language))
            return render_template(
                "register.html",
                language=language,
                algorithms=algorithm_choices,
            )

        try:
            result = encryption_manager.encrypt_password(algorithm_id, password, key_input)
        except ValueError:
            flash(translate("invalid_key", language))
            return render_template(
                "register.html",
                language=language,
                algorithms=algorithm_choices,
            )

        is_first_user = User.query.count() == 0
        user = User(
            username=username,
            encrypted_password=result.ciphertext,
            encryption_algorithm=algorithm_id,
            encryption_metadata=json.dumps(result.metadata),
            is_admin=is_first_user,
            preferred_language=language,
        )
        db.session.add(user)
        db.session.commit()
        if is_first_user:
            flash(translate("register_admin_notice", language))
        login_user(user)
        return redirect(url_for("main.dashboard"))

    return render_template(
        "register.html",
        language=language,
        algorithms=algorithm_choices,
    )


@bp.route("/login", methods=["GET", "POST"])
def login():
    language = _ensure_language()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user:
            metadata = user.metadata_dict()
            try:
                if encryption_manager.verify_password(
                    user.encryption_algorithm, password, user.encrypted_password, metadata
                ):
                    login_user(user)
                    session["language"] = user.preferred_language or language
                    return redirect(url_for("main.dashboard"))
            except KeyError:
                pass
        flash(translate("invalid_credentials", language))
    return render_template("login.html", language=language)


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.index"))


@bp.route("/dashboard")
@login_required
def dashboard():
    language = _ensure_language()
    greeting = translate("welcome_dashboard", language).format(username=current_user.username)
    return render_template("dashboard.html", language=language, greeting=greeting)


@bp.route("/theory")
@login_required
def theory_list():
    language = _ensure_language()
    theories = (
        Theory.query.filter((Theory.language == language) | (Theory.language == "all"))
        .order_by(Theory.created_at.desc())
        .all()
    )
    return render_template("theory.html", language=language, theories=theories)


@bp.route("/theory/<int:theory_id>")
@login_required
def theory_detail(theory_id: int):
    language = _ensure_language()
    theory_item = Theory.query.get_or_404(theory_id)
    return render_template("theory_detail.html", language=language, theory=theory_item)


@bp.route("/tests")
@login_required
def tests_list():
    language = _ensure_language()
    tests = (
        Test.query.filter((Test.language == language) | (Test.language == "all"))
        .order_by(Test.created_at.desc())
        .all()
    )
    return render_template("tests.html", language=language, tests=tests)


def _grade_test(test: Test, answers: Dict[int, int]) -> int:
    score = 0
    for question in test.questions:
        if answers.get(question.id) == question.correct_index:
            score += 1
    return score


@bp.route("/tests/<int:test_id>", methods=["GET", "POST"])
@login_required
def test_detail(test_id: int):
    language = _ensure_language()
    test = Test.query.get_or_404(test_id)
    if request.method == "POST":
        answers: Dict[int, int] = {}
        for question in test.questions:
            answer_value = request.form.get(str(question.id))
            if answer_value:
                try:
                    answers[question.id] = int(answer_value)
                except ValueError:
                    continue
        score = _grade_test(test, answers)
        flash(translate("score_message", language).format(score=score, total=len(test.questions)))
        return redirect(url_for("main.test_detail", test_id=test_id))
    return render_template("test_detail.html", language=language, test=test)


@bp.route("/admin", methods=["GET", "POST"])
@login_required
def admin_panel():
    language = _ensure_language()
    if not current_user.is_admin:
        flash(translate("admin_only", language))
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        form_type = request.form.get("form_type")
        if form_type == "theory":
            _handle_create_theory(language)
        elif form_type == "test":
            _handle_create_test(language)
        elif form_type == "question":
            _handle_create_question(language)
        return redirect(url_for("main.admin_panel"))

    tests = Test.query.order_by(Test.created_at.desc()).all()
    return render_template("admin.html", language=language, tests=tests)


def _handle_create_theory(language: str) -> None:
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    item_language = request.form.get("language") or language
    if not title or not content:
        flash(translate("invalid_credentials", language))
        return
    theory = Theory(
        title=title,
        content=content,
        language=item_language,
        author=current_user,
        created_at=datetime.utcnow(),
    )
    db.session.add(theory)
    db.session.commit()
    flash(translate("theory_created", language))


def _handle_create_test(language: str) -> None:
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    item_language = request.form.get("language") or language
    if not title or not description:
        flash(translate("invalid_credentials", language))
        return
    test = Test(
        title=title,
        description=description,
        language=item_language,
        author=current_user,
        created_at=datetime.utcnow(),
    )
    db.session.add(test)
    db.session.commit()
    flash(translate("test_created", language))


def _handle_create_question(language: str) -> None:
    test_id = request.form.get("test_id")
    prompt = request.form.get("prompt", "").strip()
    options_raw = request.form.get("options", "")
    correct_index_raw = request.form.get("correct_index", "")
    if not test_id or not prompt or not options_raw or not correct_index_raw:
        flash(translate("invalid_credentials", language))
        return
    try:
        test = Test.query.get(int(test_id))
    except (TypeError, ValueError):
        test = None
    if not test:
        flash(translate("invalid_credentials", language))
        return
    options = [opt.strip() for opt in options_raw.split(";") if opt.strip()]
    if len(options) < 2:
        flash(translate("invalid_credentials", language))
        return
    try:
        correct_index = int(correct_index_raw) - 1
    except ValueError:
        flash(translate("invalid_credentials", language))
        return
    if correct_index < 0 or correct_index >= len(options):
        flash(translate("invalid_credentials", language))
        return
    question = TestQuestion(
        test=test,
        prompt=prompt,
        options_json=json.dumps(options),
        correct_index=correct_index,
    )
    db.session.add(question)
    db.session.commit()
    flash(translate("question_created", language))


@bp.route("/language/<lang_code>")
def switch_language(lang_code: str):
    if lang_code in SUPPORTED_LANGUAGES:
        set_language(lang_code)
        if current_user.is_authenticated:
            current_user.preferred_language = lang_code
            db.session.commit()
    return redirect(request.referrer or url_for("main.index"))
