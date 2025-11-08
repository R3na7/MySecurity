from __future__ import annotations

import json
from datetime import datetime
import re
from typing import Any, Dict, List, Tuple

from flask import (
    Blueprint,
    flash,
    jsonify,
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


PASSWORD_POLICIES: Dict[str, Dict[str, str]] = {
    "digits_ops_digits": {
        "label": "password_policy_digits_ops_digits",
        "error": "password_policy_error_digits_ops_digits",
    },
    "not_username": {
        "label": "password_policy_not_username",
        "error": "password_policy_error_not_username",
    },
    "not_username_reversed": {
        "label": "password_policy_not_username_reversed",
        "error": "password_policy_error_not_username_reversed",
    },
    "latin_case_digits_cyrillic": {
        "label": "password_policy_latin_case_digits_cyrillic",
        "error": "password_policy_error_latin_case_digits_cyrillic",
    },
    "letters_digits_ops": {
        "label": "password_policy_letters_digits_ops",
        "error": "password_policy_error_letters_digits_ops",
    },
}


def _ensure_language():
    language = get_current_language()
    session["language"] = language
    return language


def _wants_json_response() -> bool:
    best = request.accept_mimetypes.best_match(["application/json", "text/html"])
    return (
        best == "application/json"
        and request.accept_mimetypes[best]
        > request.accept_mimetypes["text/html"]
    )


def _password_policy_choices(language: str) -> List[Tuple[str, str]]:
    choices: List[Tuple[str, str]] = []
    for policy_id, meta in PASSWORD_POLICIES.items():
        choices.append((policy_id, translate(meta["label"], language)))
    return choices


def _password_policy_description(policy_id: str | None, language: str) -> str | None:
    if not policy_id:
        return None
    meta = PASSWORD_POLICIES.get(policy_id)
    if not meta:
        return None
    return translate(meta["label"], language)


def _validate_password_policy(user: User, password: str, language: str) -> Tuple[bool, str | None]:
    policy_id = user.password_policy
    if not policy_id:
        return True, None

    if policy_id == "digits_ops_digits":
        if re.fullmatch(r"\d+[+\-*/]\d+", password):
            return True, None
    elif policy_id == "not_username":
        if password.lower() != (user.username or "").lower():
            return True, None
    elif policy_id == "not_username_reversed":
        username = user.username or ""
        if password.lower() != username[::-1].lower():
            return True, None
    elif policy_id == "latin_case_digits_cyrillic":
        has_lower = re.search(r"[a-z]", password) is not None
        has_upper = re.search(r"[A-Z]", password) is not None
        has_digit = any(ch.isdigit() for ch in password)
        has_cyrillic = re.search(r"[А-Яа-яЁё]", password) is not None
        if has_lower and has_upper and has_digit and has_cyrillic:
            return True, None
    elif policy_id == "letters_digits_ops":
        has_lower = any(ch.isalpha() and ch.islower() for ch in password)
        has_upper = any(ch.isalpha() and ch.isupper() for ch in password)
        has_digit = any(ch.isdigit() for ch in password)
        has_operator = any(ch in "+-*/" for ch in password)
        if has_lower and has_upper and has_digit and has_operator:
            return True, None

    meta = PASSWORD_POLICIES.get(policy_id)
    error_key = meta["error"] if meta else "invalid_credentials"
    return False, translate(error_key, language)


@bp.before_app_request
def _force_password_change():
    if not current_user.is_authenticated:
        return None
    endpoint = request.endpoint or ""
    allowed_endpoints = {
        "main.change_password",
        "main.logout",
        "main.switch_language",
        "static",
    }
    if current_user.must_change_password and not endpoint.startswith("static") and endpoint not in allowed_endpoints:
        return redirect(url_for("main.change_password"))
    return None


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
            if user.is_blocked:
                flash(translate("user_blocked", language))
                return render_template("login.html", language=language)
            metadata = user.metadata_dict()
            try:
                if encryption_manager.verify_password(
                    user.encryption_algorithm, password, user.encrypted_password, metadata
                ):
                    login_user(user)
                    session["language"] = user.preferred_language or language
                    if user.must_change_password:
                        flash(translate("password_change_required", language))
                        return redirect(url_for("main.change_password"))
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


@bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    language = _ensure_language()
    current_algorithm = encryption_manager.get(current_user.encryption_algorithm)
    algorithm_choices = encryption_manager.as_choices(language)
    selected_algorithm = current_algorithm
    selected_algorithm_id = current_algorithm.id
    requires_key = current_algorithm.requires_key()
    policy_hint = _password_policy_description(current_user.password_policy, language)

    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        key_input = request.form.get("encryption_key") or None
        requested_algorithm_id = (
            request.form.get("algorithm") or current_user.encryption_algorithm
        )

        try:
            selected_algorithm = encryption_manager.get(requested_algorithm_id)
        except KeyError:
            selected_algorithm = current_algorithm
            requested_algorithm_id = current_algorithm.id

        selected_algorithm_id = requested_algorithm_id
        requires_key = selected_algorithm.requires_key()

        if new_password != confirm_password:
            flash(translate("password_mismatch", language))
            return render_template(
                "change_password.html",
                language=language,
                algorithms=algorithm_choices,
                selected_algorithm_id=selected_algorithm_id,
                requires_key=requires_key,
                key_hint=selected_algorithm.get_key_hint(language),
                policy_hint=policy_hint,
                algorithm_description=selected_algorithm.get_description(language),
            )

        metadata = current_user.metadata_dict()
        try:
            if not encryption_manager.verify_password(
                current_user.encryption_algorithm,
                old_password,
                current_user.encrypted_password,
                metadata,
            ):
                flash(translate("invalid_old_password", language))
                return render_template(
                    "change_password.html",
                    language=language,
                    algorithms=algorithm_choices,
                    selected_algorithm_id=selected_algorithm_id,
                    requires_key=requires_key,
                    key_hint=selected_algorithm.get_key_hint(language),
                    policy_hint=policy_hint,
                    algorithm_description=selected_algorithm.get_description(language),
                )
        except KeyError:
            flash(translate("invalid_old_password", language))
            return render_template(
                "change_password.html",
                language=language,
                algorithms=algorithm_choices,
                selected_algorithm_id=selected_algorithm_id,
                requires_key=requires_key,
                key_hint=selected_algorithm.get_key_hint(language),
                policy_hint=policy_hint,
                algorithm_description=selected_algorithm.get_description(language),
            )

        is_valid, error_message = _validate_password_policy(current_user, new_password, language)
        if not is_valid and error_message:
            flash(error_message)
            return render_template(
                "change_password.html",
                language=language,
                algorithms=algorithm_choices,
                selected_algorithm_id=selected_algorithm_id,
                requires_key=requires_key,
                key_hint=selected_algorithm.get_key_hint(language),
                policy_hint=policy_hint,
                algorithm_description=selected_algorithm.get_description(language),
            )

        try:
            result = encryption_manager.encrypt_password(
                selected_algorithm_id,
                new_password,
                key_input,
            )
        except ValueError:
            flash(translate("invalid_key", language))
            return render_template(
                "change_password.html",
                language=language,
                algorithms=algorithm_choices,
                selected_algorithm_id=selected_algorithm_id,
                requires_key=requires_key,
                key_hint=selected_algorithm.get_key_hint(language),
                policy_hint=policy_hint,
                algorithm_description=selected_algorithm.get_description(language),
            )

        current_user.encrypted_password = result.ciphertext
        current_user.encryption_metadata = json.dumps(result.metadata)
        current_user.encryption_algorithm = selected_algorithm_id
        current_user.must_change_password = False
        db.session.commit()
        flash(translate("password_changed", language))
        return redirect(url_for("main.dashboard"))

    return render_template(
        "change_password.html",
        language=language,
        algorithms=algorithm_choices,
        selected_algorithm_id=selected_algorithm_id,
        requires_key=requires_key,
        key_hint=current_algorithm.get_key_hint(language),
        policy_hint=policy_hint,
        algorithm_description=current_algorithm.get_description(language),
    )


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
        wants_json = _wants_json_response()
        success = True
        message = None
        payload: Dict[str, object] | None = None
        if form_type == "theory":
            _handle_create_theory(language)
        elif form_type == "test":
            _handle_create_test(language)
        elif form_type == "update_theory":
            _handle_update_theory(language)
        elif form_type == "update_test":
            _handle_update_test(language)
        elif form_type == "add_questions":
            _handle_add_questions(language)
        elif form_type == "delete_question":
            _handle_delete_question(language)
        elif form_type == "create_user":
            _handle_create_user(language)
        elif form_type == "block_user":
            success, message, payload = _handle_toggle_user_block(language, block=True)
        elif form_type == "unblock_user":
            success, message, payload = _handle_toggle_user_block(language, block=False)
        elif form_type == "set_policy":
            success, message, payload = _handle_set_password_policy(language)

        if wants_json:
            response_body: Dict[str, object] = {"success": success}
            if message:
                response_body["message"] = message
            if payload:
                response_body.update(payload)
            status_code = 200 if success else 400
            return jsonify(response_body), status_code

        if message:
            flash(message)
        return redirect(url_for("main.admin_panel"))

    theories = Theory.query.order_by(Theory.created_at.desc()).all()
    tests = Test.query.order_by(Test.created_at.desc()).all()
    users = User.query.order_by(User.username).all()
    algorithm_choices = encryption_manager.as_choices(language)
    policy_choices = _password_policy_choices(language)
    policy_labels = {pid: translate(meta["label"], language) for pid, meta in PASSWORD_POLICIES.items()}
    return render_template(
        "admin.html",
        language=language,
        theories=theories,
        tests=tests,
        users=users,
        algorithms=algorithm_choices,
        policy_choices=policy_choices,
        policy_labels=policy_labels,
    )


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


def _load_questions_payload(
    language: str,
) -> Tuple[List[Dict[str, Any]], str | None]:
    payload = request.form.get("questions_payload")
    if not payload:
        return [], translate("builder_questions_required", language)
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return [], translate("invalid_credentials", language)
    if not isinstance(data, list):
        return [], translate("invalid_credentials", language)

    questions: List[Dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            return [], translate("invalid_credentials", language)
        prompt = str(item.get("prompt", "")).strip()
        if not prompt:
            return [], translate("builder_prompt_required", language)
        options_raw = item.get("options")
        if not isinstance(options_raw, list):
            return [], translate("invalid_credentials", language)
        options: List[str] = []
        for raw in options_raw:
            option_text = str(raw).strip()
            if not option_text:
                return [], translate("builder_options_required", language)
            options.append(option_text)
        if len(options) < 2:
            return [], translate("builder_options_required", language)
        correct_raw = item.get("correct_index")
        try:
            correct_index = int(correct_raw)
        except (TypeError, ValueError):
            return [], translate("builder_correct_required", language)
        if correct_index < 0 or correct_index >= len(options):
            return [], translate("builder_correct_required", language)
        questions.append(
            {
                "prompt": prompt,
                "options": options,
                "correct_index": correct_index,
            }
        )
    if not questions:
        return [], translate("builder_questions_required", language)
    return questions, None


def _handle_create_test(language: str) -> None:
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    item_language = request.form.get("language") or language
    if not title or not description:
        flash(translate("invalid_credentials", language))
        return
    questions, error = _load_questions_payload(language)
    if error:
        flash(error)
        return
    test = Test(
        title=title,
        description=description,
        language=item_language,
        author=current_user,
        created_at=datetime.utcnow(),
    )
    db.session.add(test)
    for question in questions:
        db.session.add(
            TestQuestion(
                test=test,
                prompt=question["prompt"],
                options_json=json.dumps(
                    question["options"], ensure_ascii=False
                ),
                correct_index=question["correct_index"],
            )
        )
    db.session.commit()
    flash(translate("test_created", language))


def _handle_update_theory(language: str) -> None:
    theory_id = request.form.get("theory_id")
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    item_language = request.form.get("language") or language

    if not theory_id or not title or not content:
        flash(translate("invalid_credentials", language))
        return

    try:
        theory = Theory.query.get(int(theory_id))
    except (TypeError, ValueError):
        theory = None

    if not theory:
        flash(translate("invalid_credentials", language))
        return

    theory.title = title
    theory.content = content
    theory.language = item_language
    db.session.commit()
    flash(translate("theory_updated", language))


def _handle_update_test(language: str) -> None:
    test_id = request.form.get("test_id")
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    item_language = request.form.get("language") or language

    if not test_id or not title or not description:
        flash(translate("invalid_credentials", language))
        return

    try:
        test = Test.query.get(int(test_id))
    except (TypeError, ValueError):
        test = None

    if not test:
        flash(translate("invalid_credentials", language))
        return

    test.title = title
    test.description = description
    test.language = item_language
    db.session.commit()
    flash(translate("test_updated", language))


def _handle_add_questions(language: str) -> None:
    test_id = request.form.get("test_id")
    if not test_id:
        flash(translate("invalid_credentials", language))
        return
    try:
        test = Test.query.get(int(test_id))
    except (TypeError, ValueError):
        test = None
    if not test:
        flash(translate("invalid_credentials", language))
        return
    questions, error = _load_questions_payload(language)
    if error:
        flash(error)
        return
    for question in questions:
        db.session.add(
            TestQuestion(
                test=test,
                prompt=question["prompt"],
                options_json=json.dumps(
                    question["options"], ensure_ascii=False
                ),
                correct_index=question["correct_index"],
            )
        )
    db.session.commit()
    flash(translate("questions_added", language))


def _handle_delete_question(language: str) -> None:
    question_id = request.form.get("question_id")
    if not question_id:
        flash(translate("invalid_credentials", language))
        return
    try:
        question = TestQuestion.query.get(int(question_id))
    except (TypeError, ValueError):
        question = None
    if not question:
        flash(translate("invalid_credentials", language))
        return
    db.session.delete(question)
    db.session.commit()
    flash(translate("question_removed", language))


def _handle_create_user(language: str) -> None:
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    algorithm_id = request.form.get("algorithm")
    key_input = request.form.get("encryption_key") or None

    if not username or not password or not algorithm_id:
        flash(translate("invalid_credentials", language))
        return
    if password != confirm_password:
        flash(translate("password_mismatch", language))
        return
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash(translate("user_exists", language))
        return
    try:
        result = encryption_manager.encrypt_password(algorithm_id, password, key_input)
    except ValueError:
        flash(translate("invalid_key", language))
        return

    user = User(
        username=username,
        encrypted_password=result.ciphertext,
        encryption_algorithm=algorithm_id,
        encryption_metadata=json.dumps(result.metadata),
        is_admin=False,
        preferred_language=language,
    )
    db.session.add(user)
    db.session.commit()
    flash(translate("user_created", language).format(username=username))


def _handle_toggle_user_block(
    language: str, block: bool
) -> Tuple[bool, str | None, Dict[str, object] | None]:
    user_id = request.form.get("user_id")
    if not user_id:
        return False, translate("invalid_credentials", language), None
    try:
        target = User.query.get(int(user_id))
    except (TypeError, ValueError):
        target = None
    if not target:
        return False, translate("invalid_credentials", language), None
    if target.id == current_user.id:
        return False, translate("cannot_block_self", language), None
    target.is_blocked = block
    db.session.commit()
    if block:
        message = translate("user_blocked_admin", language).format(
            username=target.username
        )
    else:
        message = translate("user_unblocked_admin", language).format(
            username=target.username
        )
    status_text = (
        translate("status_blocked", language)
        if block
        else translate("status_active", language)
    )
    policy_label = (
        translate(PASSWORD_POLICIES[target.password_policy]["label"], language)
        if target.password_policy
        else translate("password_policy_none", language)
    )
    payload = {
        "userId": target.id,
        "isBlocked": block,
        "statusText": status_text,
        "statusClass": "blocked" if block else "active",
        "nextActionLabel": translate(
            "unblock_user" if block else "block_user", language
        ),
        "nextActionFormType": "unblock_user" if block else "block_user",
        "nextActionStyle": "secondary" if block else "danger",
        "mustChangePassword": target.must_change_password,
        "passwordWarning": translate("status_password_change_required", language),
        "policyLabel": policy_label,
    }
    return True, message, payload


def _handle_set_password_policy(
    language: str,
) -> Tuple[bool, str | None, Dict[str, object] | None]:
    user_id = request.form.get("user_id")
    policy_id = request.form.get("policy_id")
    if not user_id:
        return False, translate("invalid_credentials", language), None
    try:
        target = User.query.get(int(user_id))
    except (TypeError, ValueError):
        target = None
    if not target:
        return False, translate("invalid_credentials", language), None

    if policy_id == "none" or not policy_id:
        target.password_policy = None
        target.must_change_password = False
        db.session.commit()
        message = translate("password_policy_cleared", language).format(
            username=target.username
        )
        payload = {
            "userId": target.id,
            "policyLabel": translate("password_policy_none", language),
            "requiresPasswordChange": False,
            "passwordWarning": translate(
                "status_password_change_required", language
            ),
        }
        return True, message, payload

    if policy_id not in PASSWORD_POLICIES:
        return False, translate("invalid_credentials", language), None

    target.password_policy = policy_id
    target.must_change_password = True
    db.session.commit()
    message = translate("password_policy_updated", language).format(
        username=target.username
    )
    payload = {
        "userId": target.id,
        "policyLabel": translate(PASSWORD_POLICIES[policy_id]["label"], language),
        "requiresPasswordChange": True,
        "passwordWarning": translate("status_password_change_required", language),
    }
    return True, message, payload
@bp.route("/language/<lang_code>")
def switch_language(lang_code: str):
    if lang_code in SUPPORTED_LANGUAGES:
        set_language(lang_code)
        if current_user.is_authenticated:
            current_user.preferred_language = lang_code
            db.session.commit()
    return redirect(request.referrer or url_for("main.index"))
