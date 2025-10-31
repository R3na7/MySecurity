from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

from .language import DEFAULT_LANGUAGE


db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    encryption_algorithm = db.Column(db.String(50), nullable=False)
    encryption_metadata = db.Column(db.Text, nullable=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_blocked = db.Column(db.Boolean, default=False, nullable=False)
    password_policy = db.Column(db.String(50), nullable=True)
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)
    preferred_language = db.Column(db.String(5), default=DEFAULT_LANGUAGE, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def metadata_dict(self) -> Dict[str, Any]:
        if not self.encryption_metadata:
            return {}
        try:
            return json.loads(self.encryption_metadata)
        except json.JSONDecodeError:
            return {}


class Theory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    language = db.Column(db.String(5), default=DEFAULT_LANGUAGE, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    author = db.relationship("User")


class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    language = db.Column(db.String(5), default=DEFAULT_LANGUAGE, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    author = db.relationship("User")
    questions = db.relationship(
        "TestQuestion",
        backref="test",
        cascade="all, delete-orphan",
        order_by="TestQuestion.id",
    )


class TestQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_id = db.Column(db.Integer, db.ForeignKey("test.id"), nullable=False)
    prompt = db.Column(db.Text, nullable=False)
    options_json = db.Column(db.Text, nullable=False)
    correct_index = db.Column(db.Integer, nullable=False)

    def options(self) -> List[str]:
        try:
            return json.loads(self.options_json)
        except json.JSONDecodeError:
            return []
