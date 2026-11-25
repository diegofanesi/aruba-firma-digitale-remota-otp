"""Dialogs: OTP code, missing credentials, account editing and management, support report."""

from __future__ import annotations

import html
import re

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLayout, QLineEdit,
    QListWidget, QMessageBox, QPlainTextEdit, QPushButton, QRadioButton, QVBoxLayout,
)

from .. import credentials, profiles, service
from ..errors import FirmaError
from ..models import TsaCredentials
from . import worker

TSR_NOTE = ("Con il formato TSR la marca è un file separato: se la mandi a qualcuno, manda anche il documento "
            "originale, con lo stesso nome.")

WARNING_STYLE = "color: #b3261e; font-weight: bold;"


def _label(text: str, *, wrap: bool = True, style: str = "", rich: bool = False) -> QLabel:
    """Plain text unless `rich`: Qt would otherwise render tags found in file names or aliases."""
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.RichText if rich else Qt.TextFormat.PlainText)
    label.setWordWrap(wrap)
    if style:
        label.setStyleSheet(style)
    return label


class OtpDialog(QDialog):
    """Asks for the code shown by the Aruba OTP app. Digits only; OK needs 6–8 of them."""

    def __init__(self, parent, count: int, failures: int, note: str = "", who: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Codice OTP")
        self.setMinimumWidth(620)
        layout = QVBoxLayout(self)
        if who:
            layout.addWidget(_label(f"Account: <b>{html.escape(who)}</b>", rich=True))
        layout.addWidget(_label("Apri l'app <b>Aruba OTP</b> sul telefono e scrivi qui il codice che vedi.", rich=True))
        if note:
            layout.addWidget(_label(note, style=WARNING_STYLE))
        if count > 1:
            layout.addWidget(_label(f"Con questo codice firmerai <b>{count} file</b>.", rich=True))
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
        # Keep ASCII digits only, at most 8. No setMaxLength: it would cut a pasted "1234 5678" before cleaning.
        digits = re.sub(r"[^0-9]", "", text)[:8]
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

    def __init__(self, parent, need_user: bool, store_name: str | None, who: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Account Aruba")
        self.setMinimumWidth(620)
        layout = QVBoxLayout(self)
        if who:
            layout.addWidget(_label(f"Account: <b>{html.escape(who)}</b>", rich=True))
        layout.addWidget(_label("Scrivi i dati del tuo account di firma remota Aruba." if need_user
                                else "Scrivi la password del tuo account di firma remota Aruba."))
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

    def value(self) -> tuple[tuple[str, str] | None, str, bool]:
        """((user, domain) or None if it wasn't asked, password, remember)."""
        login = credentials.split_login(self.user.text()) if self.user is not None else None
        return login, self.password.text(), bool(self.remember and self.remember.isChecked())


class ProfileEditDialog(QDialog):
    """Add or edit one account: alias, username, domain, password. Checked with Aruba (no OTP) before saving."""

    def __init__(self, parent, api_factory, store, existing: list[profiles.Profile],
                 profile: profiles.Profile | None = None):
        super().__init__(parent)
        self.api_factory, self.store = api_factory, store
        self.existing, self.editing = existing, profile
        self.profiles = existing  # the updated list once saved
        self.profile: profiles.Profile | None = None  # the saved profile
        self.setWindowTitle("Modifica account" if profile else "Nuovo account")
        self.setMinimumWidth(720)
        layout = QVBoxLayout(self)
        layout.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)  # wrapped hints never get clipped
        layout.addWidget(_label("Dati dell'account di firma remota Aruba."))
        form = QFormLayout()
        self.alias = QLineEdit(profile.alias if profile else "")
        self.alias.setPlaceholderText("come vuoi vederlo nell'elenco, per esempio il nome di chi firma")
        self.user = QLineEdit(profile.user if profile else "")
        self.user.setPlaceholderText("nome.cognome oppure nome.cognome@firma")
        self.user.editingFinished.connect(self._split_domain)
        self.domain = QLineEdit(profile.domain if profile else "firma")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.has_saved_password = bool(profile and profiles.password(store, profile))
        if self.has_saved_password:
            self.password.setPlaceholderText("lascia vuoto per non cambiarla")
        form.addRow("Nome:", self.alias)
        form.addRow("Nome utente:", self.user)
        form.addRow("Dominio di firma:", self.domain)
        form.addRow("Password:", self.password)
        layout.addLayout(form)
        hint = _label("Il dominio è quasi sempre «firma».")
        hint.setObjectName("hint")
        layout.addWidget(hint)
        self.remember = QCheckBox(f"Ricorda la password ({store.name})")
        self.remember.setChecked(self.has_saved_password if profile else True)
        layout.addWidget(self.remember)
        # Timestamps, as in Aruba Sign's settings: "Marca sempre i file firmati" and the TSA account.
        group = QGroupBox("Marca temporale")
        box = QVBoxLayout(group)
        self.timestamp = QCheckBox("Marca sempre i file firmati (data certa)")
        self.timestamp.setChecked(profile.timestamp if profile else False)
        box.addWidget(self.timestamp)
        box.addWidget(_label("Serve un servizio che includa le marche (Firma Remota con marcatura illimitata, con "
                             "«Marca automaticamente» attiva nel SelfCare) oppure un account di marca temporale.",
                             style="color: #555;"))
        saved_tsa = profiles.tsa_account(store, profile) if profile else None
        self.tsa_separate = QCheckBox("Ho un account di marca temporale (TSA) comprato a parte")
        self.tsa_separate.setChecked(saved_tsa is not None)
        box.addWidget(self.tsa_separate)
        tsa_form = QFormLayout()
        self.tsa_user = QLineEdit(saved_tsa.user if saved_tsa else "")
        self.tsa_password = QLineEdit()
        self.tsa_password.setEchoMode(QLineEdit.EchoMode.Password)
        if saved_tsa:
            self.tsa_password.setPlaceholderText("lascia vuoto per non cambiarla")
        self.tsa_url = QLineEdit(saved_tsa.url if saved_tsa and saved_tsa.url else "")
        self.tsa_url.setPlaceholderText("vuoto: il servizio di Aruba")
        tsa_form.addRow("Account TSA:", self.tsa_user)
        tsa_form.addRow("Password TSA:", self.tsa_password)
        tsa_form.addRow("Indirizzo server:", self.tsa_url)
        box.addLayout(tsa_form)
        for field in (self.tsa_user, self.tsa_password, self.tsa_url):
            field.setEnabled(self.tsa_separate.isChecked())
            self.tsa_separate.toggled.connect(field.setEnabled)
        layout.addWidget(group)
        self.saved_tsa = saved_tsa
        self.status = _label("")
        layout.addWidget(self.status)
        row = QHBoxLayout()
        row.addStretch()
        self.cancel = QPushButton("Annulla")
        self.cancel.clicked.connect(self.reject)
        self.check = QPushButton("Controlla e salva")
        self.check.setDefault(True)
        self.check.clicked.connect(self._check)
        row.addWidget(self.cancel)
        row.addWidget(self.check)
        layout.addLayout(row)
        (self.alias if profile else self.user).setFocus()

    def _split_domain(self) -> None:
        if "@" in self.user.text():
            user, domain = credentials.split_login(self.user.text())
            self.user.setText(user)
            self.domain.setText(domain)
        if not self.alias.text().strip() and self.user.text().strip():
            self.alias.setText(self.user.text().strip())

    def _set_busy(self, busy: bool, message: str = "", style: str = "") -> None:
        for widget in (self.alias, self.user, self.domain, self.password, self.remember, self.check, self.cancel,
                       self.timestamp, self.tsa_separate):
            widget.setEnabled(not busy)
        for field in (self.tsa_user, self.tsa_password, self.tsa_url):
            field.setEnabled(not busy and self.tsa_separate.isChecked())
        self.status.setText(message)
        self.status.setStyleSheet(style)

    def _check(self) -> None:
        self._split_domain()
        alias, user, domain = self.alias.text().strip(), self.user.text().strip(), self.domain.text().strip()
        password = self.password.text()
        if not password and self.has_saved_password:
            password = profiles.password(self.store, self.editing) or ""
        if not (alias and user and domain and password):
            self._set_busy(False, "Compila nome, nome utente, dominio e password.", WARNING_STYLE)
            return
        try:
            profile = profiles.new_profile(alias, user, domain, id=self.editing.id if self.editing else None,
                                           timestamp=self.timestamp.isChecked())
            clash = profiles.find(self.existing, alias)
            if clash is not None and clash.id != profile.id:
                raise FirmaError(f"C'è già un account chiamato «{clash.alias}»: scegli un altro nome.")
            self._tsa_to_save()  # validated now, saved after Aruba accepts the signing credentials
        except FirmaError as exc:
            self._set_busy(False, exc.message, WARNING_STYLE)
            return
        self._set_busy(True, "Controllo in corso con Aruba (non serve il codice OTP)...")
        job = worker.Worker(service.prepare_account, self.api_factory(), user, domain, password)
        worker.start(self, job, lambda result: self._checked(profile, password), self._failed)

    def _failed(self, exc: Exception) -> None:
        message = exc.message if isinstance(exc, FirmaError) else f"Errore imprevisto: {exc}"
        self._set_busy(False, message, WARNING_STYLE)

    def _tsa_to_save(self) -> TsaCredentials | None:
        """The separate TSA account to store, or None to use the signing credentials. Not checked with
        Aruba: every attempt would spend a mark."""
        if not self.tsa_separate.isChecked():
            return None
        user = self.tsa_user.text().strip()
        password = self.tsa_password.text() or (self.saved_tsa.password if self.saved_tsa else "")
        if not (user and password):
            raise FirmaError("Per l'account TSA separato servono nome utente e password.")
        return TsaCredentials(user, password, self.tsa_url.text().strip() or None)

    def _checked(self, profile: profiles.Profile, password: str) -> None:
        try:
            self.profiles = profiles.upsert(self.store, self.existing, profile)
            if self.remember.isChecked():
                profiles.set_password(self.store, profile, password)
            else:
                profiles.forget_password(self.store, profile)
            tsa = self._tsa_to_save()
            if tsa is not None:
                profiles.set_tsa(self.store, profile, tsa)
            else:
                profiles.forget_tsa(self.store, profile)
        except FirmaError as exc:
            self._set_busy(False, exc.message, WARNING_STYLE)
            return
        self.profile = profile
        self.accept()


class ProfilesDialog(QDialog):
    """The list of accounts, with add / edit / remove / forget-password."""

    def __init__(self, parent, api_factory, store, existing: list[profiles.Profile]):
        super().__init__(parent)
        self.api_factory, self.store = api_factory, store
        self.profiles = list(existing)
        self.setWindowTitle("Account")
        self.setMinimumSize(720, 480)
        layout = QVBoxLayout(self)
        layout.addWidget(_label("Gli account di firma salvati su questo computer. Nome utente e password stanno "
                                f"in {store.name}; sul disco non viene salvato nulla."))
        self.list = QListWidget()
        self.list.itemDoubleClicked.connect(lambda item: self.edit())
        layout.addWidget(self.list)
        self.status = _label("")
        layout.addWidget(self.status)
        row = QHBoxLayout()
        self.add_button = QPushButton("Aggiungi")
        self.edit_button = QPushButton("Modifica")
        self.remove_button = QPushButton("Rimuovi")
        self.forget_button = QPushButton("Dimentica la password")
        self.add_button.clicked.connect(self.add)
        self.edit_button.clicked.connect(self.edit)
        self.remove_button.clicked.connect(self.remove)
        self.forget_button.clicked.connect(self.forget_password)
        for button in (self.add_button, self.edit_button, self.remove_button, self.forget_button):
            row.addWidget(button)
        row.addStretch()
        close = QPushButton("Chiudi")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        layout.addLayout(row)
        self.list.currentRowChanged.connect(lambda _: self._update_buttons())
        self.refresh()

    def refresh(self, select: profiles.Profile | None = None) -> None:
        self.list.clear()
        for profile in self.profiles:
            saved = "" if profiles.password(self.store, profile) else "  (password non salvata)"
            mark = "  (con marca temporale)" if profile.timestamp else ""
            self.list.addItem(f"{profile.alias}  —  {profile.login}{saved}{mark}")
        if self.profiles:
            self.list.setCurrentRow(self.profiles.index(select) if select in self.profiles else 0)
        self._update_buttons()

    def _update_buttons(self) -> None:
        enabled = self.selected() is not None
        for button in (self.edit_button, self.remove_button, self.forget_button):
            button.setEnabled(enabled)

    def selected(self) -> profiles.Profile | None:
        row = self.list.currentRow()
        return self.profiles[row] if 0 <= row < len(self.profiles) else None

    def confirm(self, text: str) -> bool:  # seam for tests
        box = QMessageBox(QMessageBox.Icon.Question, "Conferma", text,
                          QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, parent=self)
        box.setTextFormat(Qt.TextFormat.PlainText)
        return box.exec() == QMessageBox.StandardButton.Yes

    def _edit_dialog(self, profile: profiles.Profile | None) -> None:
        dialog = ProfileEditDialog(self, self.api_factory, self.store, self.profiles, profile)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.profiles = dialog.profiles
            self.refresh(dialog.profile)
            self.status.setText(f"Account «{dialog.profile.alias}» salvato.")

    def add(self) -> None:
        self._edit_dialog(None)

    def edit(self) -> None:
        if self.selected() is not None:
            self._edit_dialog(self.selected())

    def remove(self) -> None:
        profile = self.selected()
        if profile is None or not self.confirm(f"Rimuovere l'account «{profile.alias}» da questo computer?"):
            return
        try:
            self.profiles = profiles.remove(self.store, self.profiles, profile)
        except FirmaError as exc:
            self.status.setText(exc.message)
            return
        self.refresh()
        self.status.setText(f"Account «{profile.alias}» rimosso.")

    def forget_password(self) -> None:
        profile = self.selected()
        if profile is None:
            return
        try:
            profiles.forget_password(self.store, profile)
        except FirmaError as exc:
            self.status.setText(exc.message)
            return
        self.refresh(profile)
        self.status.setText(f"Password di «{profile.alias}» dimenticata: verrà chiesta alla prossima firma.")


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


class TimestampFormatDialog(QDialog):
    """Which file a standalone timestamp produces (Aruba Sign: "Seleziona il formato di marca temporale")."""

    def __init__(self, parent, count: int):
        super().__init__(parent)
        self.setWindowTitle("Marca temporale")
        self.setMinimumWidth(720)
        layout = QVBoxLayout(self)
        layout.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)  # wrapped labels never get clipped
        what = "al file" if count == 1 else f"ai {count} file"
        layout.addWidget(_label(f"Dà data certa {what}, senza firmarli e senza codice OTP. In che formato?"))
        self.tsd = QRadioButton("TSD (consigliato)")
        self.tsr = QRadioButton("TSR")
        self.tsd.setChecked(True)
        for radio, text in ((self.tsd, "Un solo file, nome.estensione.tsd, con dentro il documento e la marca."),
                            (self.tsr, "Solo la marca, nome.estensione.tsr, da tenere insieme al documento.")):
            layout.addWidget(radio)
            hint = _label(text, style="color: #555; margin-left: 28px;")
            layout.addWidget(hint)
        self.note = _label(TSR_NOTE, style=WARNING_STYLE)
        self.note.setVisible(False)
        self.tsr.toggled.connect(self.note.setVisible)
        layout.addWidget(self.note)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Marca")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Annulla")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def value(self) -> str:
        return "tsr" if self.tsr.isChecked() else "tsd"
