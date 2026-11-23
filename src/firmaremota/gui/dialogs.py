"""Dialogs: OTP code, password, account setup, support report."""

from __future__ import annotations

import re

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
    QPlainTextEdit, QPushButton, QVBoxLayout,
)

from .. import credentials, service
from ..errors import FirmaError
from . import worker

WARNING_STYLE = "color: #b3261e; font-weight: bold;"


def _label(text: str, *, wrap: bool = True, style: str = "") -> QLabel:
    label = QLabel(text)
    label.setWordWrap(wrap)
    if style:
        label.setStyleSheet(style)
    return label


class OtpDialog(QDialog):
    """Asks for the code shown by the Aruba OTP app. Digits only; OK needs 6–8 of them."""

    def __init__(self, parent, count: int, failures: int, note: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Codice OTP")
        self.setMinimumWidth(620)
        layout = QVBoxLayout(self)
        layout.addWidget(_label("Apri l'app <b>Aruba OTP</b> sul telefono e scrivi qui il codice che vedi."))
        if note:
            layout.addWidget(_label(note, style=WARNING_STYLE))
        if count > 1:
            layout.addWidget(_label(f"Con questo codice firmerai <b>{count} file</b>."))
        self.code = QLineEdit()
        self.code.setFont(QFont(self.code.font().family(), 28))
        self.code.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.code.setPlaceholderText("12345678")
        self.code.textChanged.connect(self._clean)
        layout.addWidget(self.code)
        self.confirm = None
        if failures >= 1:
            layout.addWidget(_label(
                "Attenzione: l'ultimo tentativo è stato rifiutato. Controlla che l'ora del telefono sia "
                "giusta e usa un codice nuovo. Un altro errore potrebbe bloccare l'account.", style=WARNING_STYLE))
        if failures >= 2:
            self.confirm = QCheckBox("Ho capito, voglio riprovare")
            self.confirm.toggled.connect(self._update)
            layout.addWidget(self.confirm)
        buttons = QDialogButtonBox()
        self.ok = buttons.addButton("Firma", QDialogButtonBox.ButtonRole.AcceptRole)
        self.ok.setObjectName("big")
        buttons.addButton("Annulla", QDialogButtonBox.ButtonRole.RejectRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._update()

    def _clean(self, text: str) -> None:
        # Keep digits only, at most 8. No setMaxLength: it would cut a pasted "1234 5678" before cleaning.
        digits = re.sub(r"\D", "", text)[:8]
        if digits != text:
            self.code.setText(digits)
        self._update()

    def _update(self) -> None:
        valid = 6 <= len(self.code.text()) <= 8
        self.ok.setEnabled(valid and (self.confirm is None or self.confirm.isChecked()))

    def value(self) -> str:
        return self.code.text()


class LoginDialog(QDialog):
    """Asks for what the wallet doesn't have: the username (if needed) and the password."""

    def __init__(self, parent, need_user: bool, store_name: str | None):
        super().__init__(parent)
        self.setWindowTitle("Account Aruba")
        self.setMinimumWidth(620)
        layout = QVBoxLayout(self)
        layout.addWidget(_label("Scrivi i dati del tuo account di firma remota Aruba."))
        form = QFormLayout()
        self.user = None
        if need_user:
            self.user = QLineEdit()
            self.user.setPlaceholderText("nome.cognome@firma")
            form.addRow("Nome utente:", self.user)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Password:", self.password)
        layout.addLayout(form)
        self.remember = QCheckBox(f"Ricorda nome utente e password ({store_name})") if store_name else None
        if self.remember:
            self.remember.setChecked(True)
            layout.addWidget(self.remember)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Continua")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Annulla")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def value(self) -> tuple[tuple[str, str] | None, str, bool]:
        """((user, domain) or None if it wasn't asked, password, remember)."""
        login = credentials.split_login(self.user.text()) if self.user is not None else None
        return login, self.password.text(), bool(self.remember and self.remember.isChecked())


class SetupDialog(QDialog):
    """Username, domain and password, checked with Aruba (no OTP); kept only in the wallet, if at all."""

    def __init__(self, parent, api_factory, first_run: bool, current: tuple[str, str] | None = None):
        super().__init__(parent)
        self.api_factory = api_factory
        self.store = credentials.get_store()
        self.login: tuple[str, str] | None = current  # what is remembered after saving (None: nothing)
        self.setWindowTitle("Benvenuto" if first_run else "Impostazioni")
        self.setMinimumWidth(720)
        layout = QVBoxLayout(self)
        layout.addWidget(_label("Dati dell'account di firma remota Aruba."))
        form = QFormLayout()
        self.user = QLineEdit(current[0] if current else "")
        self.user.setPlaceholderText("nome.cognome oppure nome.cognome@firma")
        self.user.editingFinished.connect(self._split_domain)
        self.domain = QLineEdit(current[1] if current else "firma")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Nome utente:", self.user)
        form.addRow("Dominio di firma:", self.domain)
        form.addRow("Password:", self.password)
        layout.addLayout(form)
        hint = _label("Il dominio è quasi sempre «firma».")
        hint.setObjectName("hint")
        layout.addWidget(hint)
        if self.store:
            self.remember = QCheckBox(f"Ricorda nome utente e password ({self.store.name})")
            self.remember.setChecked(True)
            layout.addWidget(self.remember)
        else:
            self.remember = None
            layout.addWidget(_label("Su questo computer nome utente e password verranno chiesti a ogni firma."))
        self.status = _label("")
        layout.addWidget(self.status)
        row = QHBoxLayout()
        self.forget = QPushButton("Dimentica nome utente e password")
        self.forget.clicked.connect(self._forget)
        self.forget.setVisible(bool(self.store and current))
        row.addWidget(self.forget)
        row.addStretch()
        self.cancel = QPushButton("Annulla")
        self.cancel.clicked.connect(self.reject)
        self.check = QPushButton("Controlla e salva")
        self.check.setDefault(True)
        self.check.clicked.connect(self._check)
        row.addWidget(self.cancel)
        row.addWidget(self.check)
        layout.addLayout(row)

    def _split_domain(self) -> None:
        if "@" in self.user.text():
            user, domain = credentials.split_login(self.user.text())
            self.user.setText(user)
            self.domain.setText(domain)

    def _set_busy(self, busy: bool, message: str = "", style: str = "") -> None:
        for widget in (self.user, self.domain, self.password, self.check, self.cancel, self.forget):
            widget.setEnabled(not busy)
        self.status.setText(message)
        self.status.setStyleSheet(style)

    def _check(self) -> None:
        self._split_domain()
        user, domain, password = self.user.text().strip(), self.domain.text().strip(), self.password.text()
        if not (user and domain and password):
            self._set_busy(False, "Compila nome utente, dominio e password.", WARNING_STYLE)
            return
        self._set_busy(True, "Controllo in corso con Aruba (non serve il codice OTP)...")
        job = worker.Worker(service.prepare_account, self.api_factory(), user, domain, password)
        worker.start(self, job, lambda result: self._checked(user, domain, password), self._failed)

    def _failed(self, exc: Exception) -> None:
        message = exc.message if isinstance(exc, FirmaError) else f"Errore imprevisto: {exc}"
        self._set_busy(False, message, WARNING_STYLE)

    def _checked(self, user: str, domain: str, password: str) -> None:
        try:
            if self.store is not None:
                if self.remember is not None and self.remember.isChecked():
                    credentials.save_account(self.store, user, domain, password)
                    self.login = (user, domain)
                else:
                    credentials.forget_account(self.store)
                    self.login = None
        except credentials.CredentialStoreError as exc:
            self._set_busy(False, exc.message, WARNING_STYLE)
            return
        self.accept()

    def _forget(self) -> None:
        try:
            credentials.forget_account(self.store)
            self.login = None
            self._set_busy(False, "Nome utente e password dimenticati: verranno chiesti alla prossima firma.")
        except credentials.CredentialStoreError as exc:
            self._set_busy(False, exc.message, WARNING_STYLE)


class TextDialog(QDialog):
    """Read-only text with a 'copy' button (support report)."""

    def __init__(self, parent, title: str, intro: str, text: str):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(900, 560)
        layout = QVBoxLayout(self)
        layout.addWidget(_label(intro))
        self.text = QPlainTextEdit(text)
        self.text.setReadOnly(True)
        self.text.setFont(QFont("monospace", 11))
        layout.addWidget(self.text)
        row = QHBoxLayout()
        row.addStretch()
        copy = QPushButton("Copia")
        copy.clicked.connect(self.copy)
        close = QPushButton("Chiudi")
        close.clicked.connect(self.accept)
        row.addWidget(copy)
        row.addWidget(close)
        layout.addLayout(row)

    def copy(self) -> None:
        QGuiApplication.clipboard().setText(self.text.toPlainText())
