"""Dialogs: OTP code, password, account setup, support report."""

from __future__ import annotations

import re

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QInputDialog, QLabel, QLineEdit,
    QPlainTextEdit, QPushButton, QVBoxLayout,
)

from .. import config, credentials, service, vault
from ..errors import FirmaError
from ..models import Account
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

    def __init__(self, parent, count: int, failures: int):
        super().__init__(parent)
        self.setWindowTitle("Codice OTP")
        self.setMinimumWidth(620)
        layout = QVBoxLayout(self)
        layout.addWidget(_label("Apri l'app <b>Aruba OTP</b> sul telefono e scrivi qui il codice che vedi."))
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


class PasswordDialog(QDialog):
    def __init__(self, parent, store_name: str | None):
        super().__init__(parent)
        self.setWindowTitle("Password Aruba")
        layout = QVBoxLayout(self)
        layout.addWidget(_label("Scrivi la password del tuo account di firma Aruba."))
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password)
        self.remember = QCheckBox(f"Ricorda la password ({store_name})") if store_name else None
        if self.remember:
            self.remember.setChecked(True)
            layout.addWidget(self.remember)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Continua")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Annulla")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def value(self) -> tuple[str, bool]:
        return self.password.text(), bool(self.remember and self.remember.isChecked())


class SetupDialog(QDialog):
    """Account, domain and password; checked with Aruba (no OTP) before anything is saved."""

    def __init__(self, parent, api_factory, first_run: bool, current: vault.Profile | None = None):
        super().__init__(parent)
        self.api_factory = api_factory
        self.store = credentials.get_store()
        self.profile: vault.Profile | None = None  # set when saved
        self.setWindowTitle("Benvenuto" if first_run else "Impostazioni")
        self.setMinimumWidth(720)
        layout = QVBoxLayout(self)
        intro = ("Prima di firmare, inserisci i dati del tuo account di firma remota Aruba."
                 if first_run else "Dati dell'account di firma remota Aruba.")
        layout.addWidget(_label(intro))
        form = QFormLayout()
        self.user = QLineEdit(current.user if current else "")
        self.user.setPlaceholderText("nome.cognome oppure nome.cognome@firma")
        self.user.editingFinished.connect(self._split_domain)
        self.domain = QLineEdit(current.domain if current else "firma")
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
            self.remember = QCheckBox(f"Ricorda la password ({self.store.name})")
            self.remember.setChecked(True)
            layout.addWidget(self.remember)
        else:
            self.remember = None
            layout.addWidget(_label("Su questo computer la password verrà chiesta a ogni firma."))
        self.status = _label("")
        layout.addWidget(self.status)
        row = QHBoxLayout()
        self.forget = QPushButton("Dimentica la password salvata")
        self.forget.clicked.connect(self._forget)
        self.forget.setVisible(bool(self.store and vault.exists() and not first_run))
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
            user, domain = self.user.text().split("@", 1)
            self.user.setText(user.strip())
            self.domain.setText(domain.strip())

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
        job = worker.Worker(service.check_credentials, self.api_factory(), Account(user, domain, cert_id=""), password)
        worker.start(self, job, lambda certs: self._checked(user, domain, password, certs), self._failed)

    def _failed(self, exc: Exception) -> None:
        message = exc.message if isinstance(exc, FirmaError) else f"Errore imprevisto: {exc}"
        self._set_busy(False, message, WARNING_STYLE)

    def choose_certificate(self, certs):
        if len(certs) == 1:
            return certs[0]
        labels = [f"{signer.name}, valido fino al {signer.not_after.astimezone():%d/%m/%Y}" for _, signer in certs]
        choice, ok = QInputDialog.getItem(self, "Certificato", "Quale certificato vuoi usare?", labels, 0, False)
        return certs[labels.index(choice)] if ok else None

    def _checked(self, user: str, domain: str, password: str, certs) -> None:
        if not certs:
            self._set_busy(False, "Aruba non ha trovato certificati di firma per questo account.", WARNING_STYLE)
            return
        chosen = self.choose_certificate(certs)
        if chosen is None:
            self._set_busy(False)
            return
        cert_id, signer = chosen
        profile = vault.Profile(user, domain, cert_id, signer.name, signer.not_after.date().isoformat())
        try:
            vault.save(profile, password)
            if self.store is not None:
                if self.remember is not None and self.remember.isChecked():
                    self.store.set(credentials.PASSWORD_KEY, password)
                else:
                    self.store.delete(credentials.PASSWORD_KEY)  # an older one would no longer open the profile
                self.store.delete(credentials.legacy_key(user, domain))
        except (credentials.CredentialStoreError, OSError) as exc:
            self._set_busy(False, getattr(exc, "message", str(exc)), WARNING_STYLE)
            return
        config.save(config.load())  # drops plain-text account data left by older versions
        vault.register_personal(profile)
        self.profile = profile
        self.accept()

    def _forget(self) -> None:
        try:
            self.store.delete(credentials.PASSWORD_KEY)
            self._set_busy(False, "Password dimenticata: verrà chiesta alla prossima firma.")
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
