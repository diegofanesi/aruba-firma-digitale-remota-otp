"""Main window: one screen at a time, big buttons, every slow step off the GUI thread."""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QButtonGroup, QCheckBox, QComboBox, QFileDialog, QFrame, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit,
    QListWidget, QMainWindow, QMessageBox, QProgressBar, QPushButton, QRadioButton, QSizePolicy, QSpinBox,
    QStackedWidget, QVBoxLayout, QWidget,
)

import datetime as dt

from .. import config, credentials, diagnostics, files, messages, profiles, service, verify
from ..errors import CredentialsError, FileError, FirmaError, OriginalRequired, TimestampError
from ..logsetup import log_path, register_paths
from ..models import LAST_PAGE, JobResult, Kind, Position, SignJob, StampSpec, TimestampType, VerifyReport
from . import worker
from .dialogs import (
    TSR_NOTE, LoginDialog, OtpDialog, ProfileEditDialog, ProfilesDialog, TextDialog, TimestampFormatDialog,
)

log = logging.getLogger("firmaremota.gui")

OK_STYLE = "color: #1b7f3b;"
BAD_STYLE = "color: #b3261e;"
WARN_STYLE = "color: #9a6700;"
VERDICT_STYLES = {  # verdict -> (icon, wording, style)
    "valida": ("✔", "valida", OK_STYLE),
    "non verificabile": ("?", "NON verificabile", WARN_STYLE),
    "non valida": ("✘", "NON valida", BAD_STYLE),
}


def verdict_style(report: VerifyReport) -> tuple[str, str]:
    """(title, stylesheet) for the verify page: about the signature, or the timestamp when that's all there is."""
    icon, wording, style = VERDICT_STYLES[report.verdict]
    subject = "Firma" if report.checks else "Marca temporale"
    return f"{icon}  {subject} {wording}", style


def _label(text: str = "", name: str = "", wrap: bool = True) -> QLabel:
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)  # file names and aliases must never be rendered as HTML
    label.setWordWrap(wrap)
    if name:
        label.setObjectName(name)
    return label


def _isolated_preflight(jobs: list[SignJob], level: TimestampType | None = None) -> list[str]:
    """The local checks parse user files (PDFs): run them in a separate process with a time limit,
    so a crafted file can neither hang nor crash the window."""
    return verify.run_isolated(service.preflight, jobs, level=level, timeout=120)


def _big_button(text: str) -> QPushButton:
    button = QPushButton(text)
    button.setObjectName("big")
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    return button


def _error_text(exc: Exception) -> str:
    if isinstance(exc, FirmaError):
        return exc.message
    log.error("errore imprevisto", exc_info=exc)
    return f"Si è verificato un errore imprevisto. I dettagli sono nel registro:\n{log_path()}"


class ProfileBar(QWidget):
    """The saved accounts as big toggle buttons; clicking one makes it the account that signs."""

    chosen = Signal(str)  # profile id
    PER_ROW = 3

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.caption = _label("", "subtitle")
        layout.addWidget(self.caption)
        self.grid = QGridLayout()
        layout.addLayout(self.grid)
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        self.group.buttonClicked.connect(lambda button: self.chosen.emit(button.property("profile_id")))
        self.buttons: dict[str, QPushButton] = {}

    def refresh(self, available: list[profiles.Profile], current: profiles.Profile | None) -> None:
        for button in self.buttons.values():
            self.group.removeButton(button)
            self.grid.removeWidget(button)
            button.setParent(None)  # out of the widget tree now: deleteLater() alone would leave it painted
            button.deleteLater()
        self.buttons = {}
        if not available:
            self.caption.setText("Nessun account salvato: premi «Impostazioni» per aggiungerne uno, "
                                 "oppure firma e ti verranno chiesti nome utente e password.")
            return
        self.caption.setText("Chi firma?" if len(available) > 1 else "Account")
        for index, profile in enumerate(available):
            button = QPushButton(profile.alias)
            button.setObjectName("profile")
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setCheckable(True)
            button.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)  # never squeezed
            button.setProperty("profile_id", profile.id)
            button.setChecked(current is not None and profile.id == current.id)
            self.group.addButton(button)
            self.grid.addWidget(button, index // self.PER_ROW, index % self.PER_ROW)
            self.buttons[profile.id] = button


class HomePage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(48, 20, 48, 16)
        layout.addWidget(_label("Aruba Firma Digitale", "title"))
        self.bar = ProfileBar()
        layout.addWidget(self.bar)
        layout.addSpacing(6)
        layout.addWidget(_label("Cosa vuoi fare?", "subtitle"))
        self.sign_pdf = _big_button("Firma un PDF")
        self.sign_other = _big_button("Firma un altro file (.p7m)")
        self.timestamp_file = _big_button("Marca temporale")
        self.open_signed = _big_button("Apri un file firmato")
        for button, hint in (
            (self.sign_pdf, "Il documento resta un PDF, con la tua firma digitale."),
            (self.sign_other, "Per qualsiasi tipo di file: crea una busta firmata .p7m."),
            (self.timestamp_file, "Dà data certa a un file senza firmarlo: crea nome.estensione.tsd."),
            (self.open_signed, "Controlla se una firma o una marca è valida e apri il documento."),
        ):
            layout.addWidget(button)
            layout.addWidget(_label(hint, "hint"))
            layout.addSpacing(4)
        drop = _label("Puoi anche trascinare qui i file da firmare o da controllare.", "drop")
        drop.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(drop)
        layout.addStretch()
        row = QHBoxLayout()
        row.addStretch()
        self.settings = QPushButton("Impostazioni")
        self.support = QPushButton("Assistenza")
        row.addWidget(self.settings)
        row.addWidget(self.support)
        layout.addLayout(row)

    def refresh(self, available: list[profiles.Profile], current: profiles.Profile | None) -> None:
        self.bar.refresh(available, current)


LEVELS = {  # ArubaSign's "Tipo di marcatura"
    TimestampType.T: "T — marca nella firma (consigliato)",
    TimestampType.LT: "LT — marca con i dati di revoca, per conservare a lungo",
    TimestampType.TSD: "TSD — busta .p7m.tsd attorno al file firmato",
}


class OptionsPage(QWidget):
    """Options before signing: the timestamp (every file type) and the visible stamp (PDF only)."""

    back = Signal()
    confirm = Signal()

    def __init__(self):
        super().__init__()
        self.kind = Kind.PADES
        layout = QVBoxLayout(self)
        layout.setContentsMargins(48, 24, 48, 24)
        self.title = _label("", "title")
        layout.addWidget(self.title)
        self.files = QListWidget()
        self.files.setMaximumHeight(110)
        layout.addWidget(self.files)
        self.note = _label("", "hint")
        self.note.setStyleSheet(WARN_STYLE)
        self.note.setVisible(False)
        layout.addWidget(self.note)
        self.timestamp = QCheckBox("Marca temporale (data certa alla firma)")
        self.timestamp.setObjectName("bigcheck")
        layout.addWidget(self.timestamp)
        level_row = QHBoxLayout()
        self.level_label = QLabel("Tipo di marcatura:")
        self.level = QComboBox()
        level_row.addWidget(self.level_label)
        level_row.addWidget(self.level, 1)
        layout.addLayout(level_row)
        self.timestamp.toggled.connect(self.level.setEnabled)
        self.timestamp.toggled.connect(self.level_label.setEnabled)
        self.stamp = QCheckBox("Aggiungi un timbro visibile con la firma")
        self.stamp.setObjectName("bigcheck")
        layout.addWidget(self.stamp)
        self.where = QGroupBox("Dove mettere il timbro")
        grid = QGridLayout(self.where)
        grid.setVerticalSpacing(12)
        grid.addWidget(QLabel("Pagina:"), 0, 0)
        self.last = QRadioButton("Ultima")
        self.first = QRadioButton("Prima")
        self.numbered = QRadioButton("Numero:")
        self.number = QSpinBox()
        self.number.setRange(1, 9999)
        self.pages = QButtonGroup(self)
        for column, button in enumerate((self.last, self.first, self.numbered), start=1):
            self.pages.addButton(button)
            grid.addWidget(button, 0, column)
        grid.addWidget(self.number, 0, 4)
        grid.addWidget(QLabel("Angolo:"), 1, 0)
        self.corners = QButtonGroup(self)
        self.corner_buttons = {}
        for position, text, row, column in (
            (Position.TOP_LEFT, "In alto a sinistra", 1, 1), (Position.TOP_RIGHT, "In alto a destra", 1, 2),
            (Position.BOTTOM_LEFT, "In basso a sinistra", 2, 1), (Position.BOTTOM_RIGHT, "In basso a destra", 2, 2),
        ):
            button = QRadioButton(text)
            self.corners.addButton(button)
            self.corner_buttons[position] = button
            grid.addWidget(button, row, column)
        grid.addWidget(QLabel("Testo in più:"), 3, 0)
        self.text = QLineEdit()
        self.text.setPlaceholderText("facoltativo, per esempio «Per accettazione»")
        grid.addWidget(self.text, 3, 1, 1, 4)
        layout.addWidget(self.where)
        self.stamp.toggled.connect(self.where.setEnabled)
        layout.addStretch()
        row = QHBoxLayout()
        back = QPushButton("Indietro")
        back.clicked.connect(self.back)
        self.sign = _big_button("Firma")
        self.sign.clicked.connect(self.confirm)
        row.addWidget(back)
        row.addStretch()
        row.addWidget(self.sign)
        layout.addLayout(row)

    def load(self, settings: config.Settings, paths: list[Path], kind: Kind = Kind.PADES, timestamp: bool = True,
             note: str = "") -> None:
        self.kind = kind
        what = "PDF" if kind is Kind.PADES else "file (.p7m)"
        self.title.setText(f"Firma un {what}" if len(paths) == 1 else f"Firma {len(paths)} {what}")
        self.files.clear()
        self.files.addItems([p.name for p in paths])
        self.note.setText(note)
        self.note.setVisible(bool(note))
        self.timestamp.setChecked(timestamp)
        self.level.clear()
        for level, text in LEVELS.items():
            if level is not TimestampType.TSD or kind is Kind.CADES:
                self.level.addItem(text, level.value)
        self.level.setEnabled(timestamp)
        self.level_label.setEnabled(timestamp)
        self.stamp.setVisible(kind is Kind.PADES)
        self.where.setVisible(kind is Kind.PADES)
        self.stamp.setChecked(settings.stamp == "si")
        self.where.setEnabled(self.stamp.isChecked())
        page = settings.stamp_page
        if page == "prima":
            self.first.setChecked(True)
        elif page.isdigit():
            self.numbered.setChecked(True)
            self.number.setValue(int(page))
        else:
            self.last.setChecked(True)
        known = {p.value for p in Position}
        position = Position(settings.stamp_position) if settings.stamp_position in known else Position.BOTTOM_RIGHT
        self.corner_buttons[position].setChecked(True)

    def _page(self) -> int:
        if self.first.isChecked():
            return 1
        if self.numbered.isChecked():
            return self.number.value()
        return LAST_PAGE

    def _position(self) -> Position:
        return next(p for p, b in self.corner_buttons.items() if b.isChecked())

    def stamp_spec(self) -> StampSpec | None:
        if self.kind is not Kind.PADES or not self.stamp.isChecked():
            return None
        return StampSpec(page=self._page(), position=self._position(), text=self.text.text().strip())

    def timestamp_level(self) -> TimestampType | None:
        return TimestampType(self.level.currentData()) if self.timestamp.isChecked() else None

    def save_to(self, settings: config.Settings) -> None:
        if self.kind is not Kind.PADES:
            return
        settings.stamp = "si" if self.stamp.isChecked() else "no"
        page = self._page()
        settings.stamp_page = "ultima" if page == LAST_PAGE else "prima" if self.first.isChecked() else str(page)
        settings.stamp_position = self._position().value


class ProgressPage(QWidget):
    cancel = Signal()

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(48, 120, 48, 48)
        self.title = _label("", "title")
        self.bar = QProgressBar()
        self.current = _label("")
        self.stop = QPushButton("Annulla")
        self.stop.clicked.connect(self._cancel)
        for widget in (self.title, self.bar, self.current):
            layout.addWidget(widget)
        layout.addStretch()
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(self.stop)
        layout.addLayout(row)

    def start(self, title: str, total: int | None, cancellable: bool) -> None:
        self.title.setText(title)
        self.bar.setRange(0, total or 0)  # 0..0 = "busy" animation
        self.bar.setValue(0)
        self.current.setText("")
        self.stop.setVisible(cancellable)
        self.stop.setEnabled(True)

    def update_progress(self, done: int, total: int, name: str) -> None:
        self.bar.setValue(done)
        self.current.setText(f"Sto firmando: {name}" if name else "")

    def _cancel(self) -> None:
        self.stop.setEnabled(False)
        self.current.setText("Annullamento in corso...")
        self.cancel.emit()


class ResultPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(48, 32, 48, 24)
        self.title = _label("", "title")
        self.lines = QListWidget()
        layout.addWidget(self.title)
        layout.addWidget(self.lines)
        row = QHBoxLayout()
        self.open_document = _big_button("Apri il documento")
        self.open_folder = _big_button("Apri la cartella")
        self.retry = _big_button("Firma i rimanenti")
        for widget in (self.open_document, self.open_folder, self.retry):
            row.addWidget(widget)
        row.addStretch()
        layout.addLayout(row)
        bottom = QHBoxLayout()
        bottom.addStretch()
        self.home = QPushButton("Torna all'inizio")
        bottom.addWidget(self.home)
        layout.addLayout(bottom)

    def show_results(self, results: list[JobResult], mode: str = "sign") -> None:
        """`mode` "sign" or "timestamp". Signed files that came back with a timestamp (asked for, or applied by
        Aruba on its own) are announced as ArubaSign does: "firmato e marcato temporalmente"."""
        signed = [r for r in results if r.ok]
        total = len(results)
        timestamped = bool(signed) and all(r.timestamped for r in signed)
        if mode == "timestamp":
            one, many = "marcato", "marcati"
        else:
            one = "firmato" + (" e marcato temporalmente" if timestamped else "")
            many = "firmati" + (" e marcati temporalmente" if timestamped else "")
        self.retry.setText("Marca i rimanenti" if mode == "timestamp" else "Firma i rimanenti")
        if len(signed) == total:
            self.title.setText(f"Fatto! Documento {one}." if total == 1 else f"Fatto! {total} documenti {many}.")
            self.title.setStyleSheet(OK_STYLE)
        else:
            if not signed:
                self.title.setText(f"Nessun documento è stato {one.split()[0]}.")
            elif len(signed) == 1:
                self.title.setText(f"Attenzione: {one.split()[0]} 1 documento su {total}.")
            else:
                self.title.setText(f"Attenzione: {many.split()[0]} {len(signed)} documenti su {total}.")
            self.title.setStyleSheet(BAD_STYLE)
        self.lines.clear()
        for r in results:
            self.lines.addItem(f"✔  {r.job.src.name}  →  {r.output.name}" if r.ok
                               else f"✘  {r.job.src.name}: {r.error.message}")
        self.open_document.setVisible(len(signed) == 1)
        self.open_folder.setVisible(bool(signed))
        self.retry.setVisible(bool(retryable(results)))


def retryable(results: list[JobResult]) -> list[SignJob]:
    """Files not signed because of the service or a cancel (local file problems need fixing first)."""
    return [r.job for r in results if not r.ok and not isinstance(r.error, FileError)]


class VerifyPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(48, 32, 48, 24)
        self.title = _label("", "title")
        self.file = _label("", "hint")
        self.details = QListWidget()
        self.details.setWordWrap(True)
        layout.addWidget(self.title)
        layout.addWidget(self.file)
        layout.addWidget(self.details)
        row = QHBoxLayout()
        self.open_document = _big_button("Apri il documento")
        self.open_folder = _big_button("Apri la cartella")
        self.home = QPushButton("Torna all'inizio")
        row.addWidget(self.open_document)
        row.addWidget(self.open_folder)
        row.addStretch()
        row.addWidget(self.home)
        layout.addLayout(row)

    def show_report(self, report: VerifyReport, path: Path) -> None:
        title, style = verdict_style(report)
        self.title.setText(title)
        self.title.setStyleSheet(style)
        self.file.setText(str(path))
        self.details.clear()
        for index, check in enumerate(report.checks, start=1):
            if len(report.checks) > 1:
                self.details.addItem(f"— Firma {index} di {len(report.checks)} —")
            self.details.addItems(messages.check_lines(check)[1:])
        self.details.addItems(messages.timestamp_lines(report))
        openable = (report.kind is Kind.PADES and report.content is None) or (
            report.content is not None and files.safe_to_open(report.content_name))
        if report.content_name:
            self.details.addItem(f"Documento contenuto: {report.content_name}")
            if not openable:
                self.details.addItem(f"Il documento contenuto è di tipo «{Path(report.content_name).suffix or '?'}», "
                                     "che per sicurezza non viene aperto automaticamente: lo trovi nella cartella "
                                     "del file e puoi aprirlo tu, se ti fidi di chi lo ha mandato.")
        self.details.addItem(messages.trust_list_line(report))
        self.open_document.setVisible(openable)
        self.open_folder.setVisible(report.content is not None)


class MainWindow(QMainWindow):
    def __init__(self, api_factory):
        super().__init__()
        self.api_factory = api_factory
        self._api = None
        self.setWindowTitle("Aruba Firma Digitale")
        self.setMinimumSize(1000, 700)
        self.setAcceptDrops(True)
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        self.home, self.options, self.progress = HomePage(), OptionsPage(), ProgressPage()
        self.result, self.verify_page = ResultPage(), VerifyPage()
        for page in (self.home, self.options, self.progress, self.result, self.verify_page):
            self.stack.addWidget(page)

        self.home.sign_pdf.clicked.connect(self.sign_pdf)
        self.home.sign_other.clicked.connect(self.sign_other)
        self.home.timestamp_file.clicked.connect(self.timestamp_files)
        self.home.open_signed.clicked.connect(self.open_signed)
        self.home.settings.clicked.connect(self.manage_profiles)
        self.home.bar.chosen.connect(self.select_profile)
        self.home.support.clicked.connect(self.support)
        self.options.back.connect(self.go_home)
        self.options.confirm.connect(self.options_confirmed)
        self.progress.cancel.connect(lambda: self.cancel_event and self.cancel_event.set())
        self.result.home.clicked.connect(self.go_home)
        self.result.open_document.clicked.connect(self.open_signed_document)
        self.result.open_folder.clicked.connect(self.open_result_folder)
        self.result.retry.clicked.connect(self.retry_remaining)
        self.verify_page.home.clicked.connect(self.go_home)
        self.verify_page.open_document.clicked.connect(self.open_verified_document)
        self.verify_page.open_folder.clicked.connect(self.open_verified_folder)

        self.paths: list[Path] = []
        self.results: list[JobResult] = []
        self.report: VerifyReport | None = None
        self.report_path: Path | None = None
        self.extracted: Path | None = None
        self.cancel_event: threading.Event | None = None
        self.pending: dict | None = None  # a signing run between the account check and the OTP
        self.mode = "sign"  # what the result page is about: "sign" or "timestamp"
        self.last_level: TimestampType | None = None
        self.verify_fn = verify.verify_file_isolated  # (path, cancel) -> VerifyReport; tests swap it
        self.preflight_fn = _isolated_preflight  # (jobs, level) -> problems; tests swap it
        self.store: credentials.Store | None = None
        self.profiles: list[profiles.Profile] = []
        self.current: profiles.Profile | None = None  # the account that signs
        self._load_profiles()
        self.go_home()

    # --- seams: everything that asks the user something (tests replace these) ---------------

    def choose_files(self, title: str, filters: str, multiple: bool = True) -> list[str]:
        if multiple:
            return QFileDialog.getOpenFileNames(self, title, str(Path.home()), filters)[0]
        path = QFileDialog.getOpenFileName(self, title, str(Path.home()), filters)[0]
        return [path] if path else []

    def ask_otp(self, count: int, failures: int, note: str = "", who: str = "") -> str | None:
        dialog = OtpDialog(self, count, failures, note, who)
        return dialog.value() if dialog.exec() == OtpDialog.DialogCode.Accepted else None

    def ask_login(self, need_user: bool, store_name: str | None, who: str = ""):
        """((user, domain) or None, password, remember), or None if cancelled."""
        dialog = LoginDialog(self, need_user, store_name, who)
        if dialog.exec() != LoginDialog.DialogCode.Accepted:
            return None
        login, password, remember = dialog.value()
        if not password or (need_user and not (login and login[0])):
            return None
        return login, password, remember

    def ask_timestamp_format(self, count: int) -> str | None:
        """'tsd' or 'tsr', or None if cancelled."""
        dialog = TimestampFormatDialog(self, count)
        return dialog.value() if dialog.exec() == TimestampFormatDialog.DialogCode.Accepted else None

    def choose_original(self, name: str) -> str | None:
        """The document a detached .tsr timestamp refers to."""
        paths = self.choose_files(f"Scegli il documento a cui si riferisce la marca {name}", "Tutti i file (*)",
                                  multiple=False)
        return paths[0] if paths else None

    def ask_yes_no(self, title: str, text: str) -> bool:
        box = QMessageBox(QMessageBox.Icon.Question, title, text, QMessageBox.StandardButton.Yes
                          | QMessageBox.StandardButton.No, parent=self)
        box.setTextFormat(Qt.TextFormat.PlainText)
        return box.exec() == QMessageBox.StandardButton.Yes

    def ask_sign_or_verify(self, name: str) -> str | None:
        box = QMessageBox(QMessageBox.Icon.Question, "Cosa vuoi fare?", f"Cosa vuoi fare con {name}?", parent=self)
        box.setTextFormat(Qt.TextFormat.PlainText)
        sign = box.addButton("Firmarlo", QMessageBox.ButtonRole.AcceptRole)
        check = box.addButton("Controllare la firma", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Annulla", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        return {sign: "firma", check: "verifica"}.get(box.clickedButton())

    def show_error(self, title: str, text: str) -> None:
        box = QMessageBox(QMessageBox.Icon.Warning, title, text, QMessageBox.StandardButton.Ok, parent=self)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.exec()

    def manage_profiles(self) -> None:
        if self.store is None:
            self.show_error("Portachiavi", "Su questo computer non c'è un portachiavi (KWallet o Secret Service): "
                            "gli account non si possono salvare, nome utente e password verranno chiesti a ogni firma.")
            return
        dialog = ProfilesDialog(self, lambda: self.api, self.store, self.profiles)
        dialog.exec()
        self._set_profiles(dialog.profiles, profiles.by_id(dialog.profiles, self.current.id if self.current else None))

    def add_first_profile(self) -> bool:
        """No account saved yet: add one (checked with Aruba, no OTP). True if one was added."""
        dialog = ProfileEditDialog(self, lambda: self.api, self.store, self.profiles)
        if dialog.exec() != ProfileEditDialog.DialogCode.Accepted:
            return False
        self._set_profiles(dialog.profiles, dialog.profile)
        return True

    def open_url(self, path: Path) -> None:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    # --- navigation and drops ------------------------------------------------------------------

    @property
    def api(self):
        if self._api is None:
            self._api = self.api_factory()
        return self._api

    def go_home(self) -> None:
        self.home.refresh(self.profiles, self.current)
        self.stack.setCurrentWidget(self.home)

    def _load_profiles(self) -> None:
        try:
            self.store = credentials.get_store()
            available = profiles.load_all(self.store) if self.store else []
        except credentials.CredentialStoreError as exc:
            log.info("portachiavi non disponibile all'avvio: %s", exc.message)
            available = []
        self._set_profiles(available, profiles.by_id(available, config.load().last_profile))

    def _set_profiles(self, available: list[profiles.Profile], current: profiles.Profile | None) -> None:
        self.profiles = available
        self.current = current or (available[0] if available else None)
        settings = config.load()
        wanted = self.current.id if self.current else ""
        if settings.last_profile != wanted:
            settings.last_profile = wanted
            config.save(settings)
        self.home.refresh(self.profiles, self.current)

    def select_profile(self, profile_id: str) -> None:
        self._set_profiles(self.profiles, profiles.by_id(self.profiles, profile_id))

    def busy(self) -> bool:
        return any(not thread.isFinished() for thread, _ in self.__dict__.get("_running_workers", []))

    def closeEvent(self, event) -> None:
        """A running worker thread must not be destroyed with the window (Qt would abort)."""
        if self.busy():
            self.progress.current.setText("Attendi la fine dell'operazione in corso prima di chiudere.")
            event.ignore()
            return
        event.accept()

    def dragEnterEvent(self, event) -> None:
        if self.stack.currentWidget() is self.home and event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        self.open_paths([url.toLocalFile() for url in event.mimeData().urls() if url.isLocalFile()])

    def open_paths(self, paths: list[str]) -> None:
        """Files dropped on the window or passed on the command line."""
        paths = [p for p in paths if Path(p).is_file()]
        if not paths:
            return
        pdfs = [p for p in paths if p.lower().endswith(".pdf")]
        if len(paths) == 1 and paths[0].lower().endswith((".p7m", ".tsd", ".tsr")):
            self.verify(paths[0])
        elif len(paths) == 1 and pdfs:
            choice = self.ask_sign_or_verify(Path(paths[0]).name)
            if choice == "verifica":
                self.verify(paths[0])
            elif choice == "firma":
                self.prepare_sign(paths, Kind.PADES)
        elif len(pdfs) == len(paths):
            self.prepare_sign(paths, Kind.PADES)
        elif self.ask_yes_no("Firmare?", f"Firmare {len(paths)} file creando buste .p7m?"):
            self.prepare_sign(paths, Kind.CADES)

    # --- signing -------------------------------------------------------------------------------

    def sign_pdf(self) -> None:
        paths = self.choose_files("Scegli i PDF da firmare", "Documenti PDF (*.pdf *.PDF)")
        if paths:
            self.prepare_sign(paths, Kind.PADES)

    def sign_other(self) -> None:
        paths = self.choose_files("Scegli i file da firmare", "Tutti i file (*)")
        if paths:
            self.prepare_sign(paths, Kind.CADES)

    def timestamp_default(self) -> bool:
        return self.current.timestamp if self.current else False

    def prepare_sign(self, paths: list[str], kind: Kind, note: str = "", timestamp: bool | None = None) -> None:
        self.paths = [Path(p) for p in paths]
        wanted = self.timestamp_default() if timestamp is None else timestamp
        self.options.load(config.load(), self.paths, kind, wanted, note)
        self.stack.setCurrentWidget(self.options)

    def options_confirmed(self) -> None:
        settings = config.load()
        self.options.save_to(settings)
        config.save(settings)
        kind, spec = self.options.kind, self.options.stamp_spec()
        self.sign([SignJob(p, kind, spec) for p in self.paths], level=self.options.timestamp_level())

    def retry_remaining(self) -> None:
        jobs = retryable(self.results)
        if not jobs:
            return
        if self.mode == "timestamp":
            self.timestamp([str(j.src) for j in jobs], jobs[0].kind)
        elif any(isinstance(r.error, TimestampError) for r in self.results):
            # the timestamp is what failed: offer the same files with the box unticked
            self.prepare_sign([str(j.src) for j in jobs], jobs[0].kind, timestamp=False,
                              note="La marca temporale non è stata applicata: puoi firmare senza, o riprovare.")
        else:
            self.sign(jobs, level=self.last_level)

    def credentials_for_signing(self):
        """(user, domain, password, remember, profile): from the wallet, asking only for what's missing."""
        if self.store is None:  # nothing can be saved on this computer: ask for everything, remember nothing
            answer = self.ask_login(need_user=True, store_name=None)
            if answer is None:
                return None
            (user, domain), password, _ = answer
            return user, domain, password, False, None
        if not self.profiles and not self.add_first_profile():
            return None
        profile = self.current
        try:
            password = profiles.password(self.store, profile)
        except credentials.CredentialStoreError as exc:
            self.show_error("Portachiavi", exc.message)
            password = None
        remember = False
        if not password:
            answer = self.ask_login(need_user=False, store_name=self.store.name, who=profile.alias)
            if answer is None:
                return None
            _, password, remember = answer
        return profile.user, profile.domain, password, remember, profile

    def confirm_after_failures(self) -> bool:
        """The same guard the command line has: after a refused login, nothing is sent to Aruba without a
        yes from the user (a few refusals in a row can lock the account)."""
        failures = service.auth_failures()
        if failures == 0:
            return True
        return self.ask_yes_no("Attenzione", f"L'ultimo accesso al servizio di firma è stato rifiutato ({failures} di "
                               "fila). Un altro errore potrebbe bloccare l'account Aruba.\n\nRiprovare comunque?")

    def sign(self, jobs: list[SignJob], level: TimestampType | None = None) -> None:
        """Local checks (in a separate process), then the account check with Aruba (no OTP), then the OTP,
        then signing."""
        self.mode, self.last_level = "sign", level
        self.progress.start("Controllo dei file...", total=None, cancellable=False)
        self.stack.setCurrentWidget(self.progress)
        job = worker.Worker(self.preflight_fn, jobs, level=level)
        worker.start(self, job, lambda problems: self._sign_checked(jobs, level, problems), self.sign_failed)

    def _sign_checked(self, jobs: list[SignJob], level: TimestampType | None, problems: list[str]) -> None:
        self.go_home()
        if problems:
            self.show_error("Impossibile firmare", "\n".join(problems) + "\n\nNon è stato usato nessun codice OTP.")
            return
        jobs = service.fingerprint(jobs)  # a file that changes from now on is refused at signing time
        found = self.credentials_for_signing()
        if found is None:
            return
        user, domain, password, remember, profile = found
        problem = service.needs_tsa_account(level, profiles.tsa_credentials(self.store, profile))
        if problem:
            self.show_error("Serve un account di marca temporale", problem + "\n\nNon è stato usato nessun codice OTP.")
            return
        if not self.confirm_after_failures():
            return
        self._check_account(jobs, level, user, domain, password, remember, profile)

    def _check_account(self, jobs, level, user, domain, password, remember, profile) -> None:
        """Ask Aruba to accept the password (no OTP) before anything else is asked of the user."""
        self.pending = {"jobs": jobs, "password": password, "remember": remember, "profile": profile,
                        "who": profile.alias if profile else f"{user}@{domain}", "level": level, "user": user,
                        "domain": domain}
        self.progress.start("Controllo dell'account con Aruba...", total=None, cancellable=False)
        self.stack.setCurrentWidget(self.progress)
        job = worker.Worker(service.prepare_account, self.api, user, domain, password, config.load())
        worker.start(self, job, self.account_ready, self.sign_failed)

    def account_ready(self, result) -> None:
        account, signer = result
        pending, self.pending = self.pending, None
        if pending["remember"] and pending["profile"] and self.store:  # Aruba accepted it: it may go into the wallet
            try:
                profiles.set_password(self.store, pending["profile"], pending["password"])
            except credentials.CredentialStoreError as exc:
                log.warning("password non salvata: %s", exc.message)
        note = ""
        if signer.not_after - dt.datetime.now(dt.timezone.utc) < dt.timedelta(days=60):
            note = f"Attenzione: il certificato di firma scade il {signer.not_after.astimezone():%d/%m/%Y}."
        jobs = pending["jobs"]
        otp = self.ask_otp(len(jobs), service.auth_failures(), note, pending["who"])
        if otp is None:
            self.go_home()
            return
        self.cancel_event = threading.Event()
        level = pending["level"]
        tsa = profiles.tsa_credentials(self.store, pending["profile"]) if level else None
        self.progress.start("Firma in corso..." + (" con marca temporale" if level else ""), total=len(jobs),
                            cancellable=len(jobs) > 1)
        job = worker.Worker(service.sign_batch, self.api, account, pending["password"], otp, jobs,
                            signer_name=signer.name, cancel=self.cancel_event, tsa=tsa, level=level)
        job.kwargs["progress"] = job.report
        worker.start(self, job, self.sign_done, self.sign_failed, self.progress.update_progress)

    def sign_done(self, results: list[JobResult]) -> None:
        self.results = results
        self.result.show_results(results)
        self.stack.setCurrentWidget(self.result)

    # --- standalone timestamps --------------------------------------------------------------------

    def tsa_for_marks(self):
        """The TSA account of the current profile, or None after explaining why standalone marks need one."""
        tsa = profiles.tsa_credentials(self.store, self.current) if self.store and self.current else None
        if tsa is None:
            self.show_error("Serve un account di marca temporale", service.NO_TSA_ACCOUNT)
        return tsa

    def timestamp_files(self) -> None:
        paths = self.choose_files("Scegli i file a cui dare data certa", "Tutti i file (*)")
        if not paths or self.tsa_for_marks() is None:
            return
        fmt = self.ask_timestamp_format(len(paths))
        if fmt:
            self.timestamp(paths, Kind.TSR if fmt == "tsr" else Kind.TSD)

    def timestamp(self, paths: list[str], kind: Kind) -> None:
        """Local checks (in a separate process), the TSA account saved for the current profile (no check with
        Aruba: it would spend a mark), then the timestamps. Firma Remota's included marks don't apply here."""
        jobs = [SignJob(Path(p), kind) for p in paths]
        self.mode = "timestamp"
        self.progress.start("Controllo dei file...", total=None, cancellable=False)
        self.stack.setCurrentWidget(self.progress)
        job = worker.Worker(self.preflight_fn, jobs)
        worker.start(self, job, lambda problems: self._timestamp_checked(jobs, problems), self.sign_failed)

    def _timestamp_checked(self, jobs: list[SignJob], problems: list[str]) -> None:
        self.go_home()
        if problems:
            self.show_error("Impossibile marcare", "\n".join(problems))
            return
        jobs = service.fingerprint(jobs)
        tsa = self.tsa_for_marks()
        if tsa is None:
            return
        self.cancel_event = threading.Event()
        self.progress.start("Marca temporale in corso...", total=len(jobs), cancellable=len(jobs) > 1)
        self.stack.setCurrentWidget(self.progress)
        job = worker.Worker(service.timestamp_batch, self.api, tsa, jobs, cancel=self.cancel_event)
        job.kwargs["progress"] = job.report
        worker.start(self, job, self.timestamp_done, self.sign_failed, self.progress.update_progress)

    def timestamp_done(self, results: list[JobResult]) -> None:
        self.results = results
        self.result.show_results(results, mode="timestamp")
        if any(r.ok and r.job.kind is Kind.TSR for r in results):
            self.result.lines.addItem(f"ℹ  {TSR_NOTE}")
        self.stack.setCurrentWidget(self.result)

    def sign_failed(self, exc: Exception) -> None:
        pending, self.pending = self.pending, None
        self.go_home()
        if isinstance(exc, CredentialsError) and pending and pending["profile"] and self.store:
            # Aruba refused the password (saved, or just typed): offer to type it again instead of leaving
            # a wrong one in place, where every further click would cost another refusal
            if self.ask_yes_no("Password non accettata", _error_text(exc) + "\n\nVuoi scrivere di nuovo la password?"):
                answer = self.ask_login(need_user=False, store_name=self.store.name, who=pending["who"])
                if answer is not None:
                    _, password, remember = answer
                    self._check_account(pending["jobs"], pending["level"], pending["user"], pending["domain"],
                                        password, remember, pending["profile"])
            return
        self.show_error("Firma non riuscita" if self.mode == "sign" else "Marca temporale non riuscita", _error_text(exc))

    def open_signed_document(self) -> None:
        signed = [r for r in self.results if r.ok]
        if signed:
            self.open_url(signed[0].output)

    def open_result_folder(self) -> None:
        signed = [r for r in self.results if r.ok]
        if signed:
            self.open_url(signed[0].output.parent)

    # --- verification ------------------------------------------------------------------------

    def open_signed(self) -> None:
        paths = self.choose_files("Scegli il file firmato o marcato",
                                  "File firmati o marcati (*.pdf *.p7m *.tsd *.tsr *.PDF *.P7M *.TSD *.TSR);;Tutti i file (*)",
                                  multiple=False)
        if paths:
            self.verify(paths[0])

    def verify(self, path: str, original: Path | None = None) -> None:
        self.report_path, self.extracted = Path(path), None
        self.cancel_event = threading.Event()
        self.progress.start("Controllo della firma in corso...", total=None, cancellable=True)
        self.progress.current.setText("La prima volta può richiedere qualche secondo.")
        self.stack.setCurrentWidget(self.progress)
        job = worker.Worker(self.verify_fn, self.report_path, cancel=self.cancel_event, original=original)
        worker.start(self, job, self.verify_done, self.verify_failed)

    def verify_done(self, report: VerifyReport) -> None:
        self.report = report
        self.verify_page.show_report(report, self.report_path)
        self.stack.setCurrentWidget(self.verify_page)

    def verify_failed(self, exc: Exception) -> None:
        if isinstance(exc, OriginalRequired):  # a .tsr alone says nothing: ask which file it belongs to
            chosen = self.choose_original(self.report_path.name)
            if chosen:
                self.verify(str(self.report_path), original=Path(chosen))
            else:
                self.go_home()  # the user gave up: nothing went wrong
            return
        self.go_home()
        self.show_error("Controllo non riuscito", _error_text(exc))

    def extract_verified(self) -> Path | None:
        """The document inside the verified .p7m, written next to it (once); None if there is none."""
        if self.report is None or self.report.content is None:
            return None
        if self.extracted is None:
            try:
                self.extracted = files.write_new(self.report_path.parent, self.report.content_name, self.report.content)
            except FileError as exc:
                self.show_error("Impossibile estrarre il documento", exc.message)
                return None
        return self.extracted

    def open_verified_document(self) -> None:
        if self.report is None:
            return
        register_paths(self.report_path)
        if self.report.content is None:  # a signed PDF the user chose: open it as it is
            self.open_url(self.report_path)
            return
        if not files.safe_to_open(self.report.content_name):
            return  # the button is hidden for these; never launch a sender-chosen file type
        extracted = self.extract_verified()
        if extracted is not None:
            self.open_url(extracted)

    def open_verified_folder(self) -> None:
        extracted = self.extract_verified()
        if extracted is not None:
            self.open_url(extracted.parent)

    # --- support -----------------------------------------------------------------------------

    def support(self) -> None:
        if not self.confirm_after_failures():  # the report sends the saved password to Aruba
            return
        self.progress.start("Controllo in corso...", total=None, cancellable=False)
        self.stack.setCurrentWidget(self.progress)
        job = worker.Worker(diagnostics.report, self.api, check_credentials=True,
                            only_profile_id=self.current.id if self.current else None)
        worker.start(self, job, self.support_done, self.verify_failed)

    def support_done(self, lines) -> None:
        self.go_home()
        self.show_support(diagnostics.as_text(lines))

    def show_support(self, text: str) -> None:
        TextDialog(self, "Assistenza", "Se qualcosa non funziona, premi «Copia» e incolla queste informazioni "
                   "in un messaggio a chi ti aiuta. Non contengono la password. Le credenziali controllate con "
                   "Aruba sono solo quelle dell'account selezionato.", text).exec()
