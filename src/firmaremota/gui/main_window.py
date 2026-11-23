"""Main window: one screen at a time, big buttons, every slow step off the GUI thread."""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QButtonGroup, QCheckBox, QFileDialog, QFrame, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit,
    QListWidget, QMainWindow, QMessageBox, QProgressBar, QPushButton, QRadioButton, QSpinBox, QStackedWidget,
    QVBoxLayout, QWidget,
)

from .. import config, credentials, diagnostics, files, messages, service, vault, verify
from ..errors import FileError, FirmaError
from ..logsetup import log_path, register_paths
from ..models import LAST_PAGE, JobResult, Kind, Position, SignJob, StampSpec, VerifyReport
from . import worker
from .dialogs import OtpDialog, PasswordDialog, SetupDialog, TextDialog

log = logging.getLogger("firmaremota.gui")

OK_STYLE = "color: #1b7f3b;"
BAD_STYLE = "color: #b3261e;"


def _label(text: str = "", name: str = "", wrap: bool = True) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(wrap)
    if name:
        label.setObjectName(name)
    return label


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


class HomePage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(48, 32, 48, 24)
        layout.addWidget(_label("Firma remota", "title"))
        layout.addWidget(_label("Cosa vuoi fare?", "subtitle"))
        layout.addSpacing(16)
        self.sign_pdf = _big_button("Firma un PDF")
        self.sign_other = _big_button("Firma un altro file (.p7m)")
        self.open_signed = _big_button("Apri un file firmato")
        for button, hint in (
            (self.sign_pdf, "Il documento resta un PDF, con la tua firma digitale."),
            (self.sign_other, "Per qualsiasi tipo di file: crea una busta firmata .p7m."),
            (self.open_signed, "Controlla se una firma è valida e apri il documento firmato."),
        ):
            layout.addWidget(button)
            layout.addWidget(_label(hint, "hint"))
            layout.addSpacing(10)
        drop = _label("Puoi anche trascinare qui i file da firmare o da controllare.", "drop")
        drop.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(drop)
        layout.addStretch()
        row = QHBoxLayout()
        self.account = _label("", "hint", wrap=False)
        row.addWidget(self.account)
        row.addStretch()
        self.settings = QPushButton("Impostazioni")
        self.support = QPushButton("Assistenza")
        row.addWidget(self.settings)
        row.addWidget(self.support)
        layout.addLayout(row)

    def refresh(self, profile: vault.Profile | None) -> None:
        if profile is not None:
            self.account.setText(f"Account: {profile.login}")
        else:
            self.account.setText("Account configurato" if vault.exists() else "Account non configurato")


class OptionsPage(QWidget):
    """Visible stamp options for PDF signing."""

    back = Signal()
    confirm = Signal()

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(48, 24, 48, 24)
        self.title = _label("", "title")
        layout.addWidget(self.title)
        self.files = QListWidget()
        self.files.setMaximumHeight(110)
        layout.addWidget(self.files)
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

    def load(self, settings: config.Settings, paths: list[Path]) -> None:
        self.title.setText("Firma un PDF" if len(paths) == 1 else f"Firma {len(paths)} PDF")
        self.files.clear()
        self.files.addItems([p.name for p in paths])
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
        if not self.stamp.isChecked():
            return None
        return StampSpec(page=self._page(), position=self._position(), text=self.text.text().strip())

    def save_to(self, settings: config.Settings) -> None:
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
        self.current.setText("Annullo dopo il file in corso...")
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

    def show_results(self, results: list[JobResult]) -> None:
        signed = [r for r in results if r.ok]
        total = len(results)
        if len(signed) == total:
            self.title.setText("Fatto! Documento firmato." if total == 1 else f"Fatto! {total} documenti firmati.")
            self.title.setStyleSheet(OK_STYLE)
        else:
            if not signed:
                self.title.setText("Nessun documento è stato firmato.")
            elif len(signed) == 1:
                self.title.setText(f"Attenzione: firmato 1 documento su {total}.")
            else:
                self.title.setText(f"Attenzione: firmati {len(signed)} documenti su {total}.")
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
        self.home = QPushButton("Torna all'inizio")
        row.addWidget(self.open_document)
        row.addStretch()
        row.addWidget(self.home)
        layout.addLayout(row)

    def show_report(self, report: VerifyReport, path: Path) -> None:
        self.title.setText("✔  Firma valida" if report.ok else "✘  Firma NON valida")
        self.title.setStyleSheet(OK_STYLE if report.ok else BAD_STYLE)
        self.file.setText(str(path))
        self.details.clear()
        for index, check in enumerate(report.checks, start=1):
            if len(report.checks) > 1:
                self.details.addItem(f"— Firma {index} di {len(report.checks)} —")
            self.details.addItems(messages.check_lines(check)[1:])
        if report.content_name:
            self.details.addItem(f"Documento contenuto: {report.content_name}")
        self.details.addItem(messages.trust_list_line(report))
        self.open_document.setVisible(report.content is not None or report.kind is Kind.PADES)


class MainWindow(QMainWindow):
    def __init__(self, api_factory):
        super().__init__()
        self.api_factory = api_factory
        self._api = None
        self.setWindowTitle("Firma remota")
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
        self.home.open_signed.clicked.connect(self.open_signed)
        self.home.settings.clicked.connect(lambda: self.run_setup(first_run=False))
        self.home.support.clicked.connect(self.support)
        self.options.back.connect(self.go_home)
        self.options.confirm.connect(self.options_confirmed)
        self.progress.cancel.connect(lambda: self.cancel_event and self.cancel_event.set())
        self.result.home.clicked.connect(self.go_home)
        self.result.open_document.clicked.connect(self.open_signed_document)
        self.result.open_folder.clicked.connect(self.open_result_folder)
        self.result.retry.clicked.connect(lambda: self.sign(retryable(self.results)))
        self.verify_page.home.clicked.connect(self.go_home)
        self.verify_page.open_document.clicked.connect(self.open_verified_document)

        self.paths: list[Path] = []
        self.results: list[JobResult] = []
        self.report: VerifyReport | None = None
        self.report_path: Path | None = None
        self.extracted: Path | None = None
        self.cancel_event: threading.Event | None = None
        self.pending_password: str | None = None
        self.profile: vault.Profile | None = None  # decrypted account data, kept in memory only
        self._unlock_quietly()
        self.go_home()

    # --- seams: everything that asks the user something (tests replace these) ---------------

    def choose_files(self, title: str, filters: str, multiple: bool = True) -> list[str]:
        if multiple:
            return QFileDialog.getOpenFileNames(self, title, str(Path.home()), filters)[0]
        path = QFileDialog.getOpenFileName(self, title, str(Path.home()), filters)[0]
        return [path] if path else []

    def ask_otp(self, count: int, failures: int) -> str | None:
        dialog = OtpDialog(self, count, failures)
        return dialog.value() if dialog.exec() == OtpDialog.DialogCode.Accepted else None

    def ask_password(self, store_name: str | None) -> tuple[str, bool] | None:
        dialog = PasswordDialog(self, store_name)
        if dialog.exec() != PasswordDialog.DialogCode.Accepted or not dialog.value()[0]:
            return None
        return dialog.value()

    def ask_yes_no(self, title: str, text: str) -> bool:
        return QMessageBox.question(self, title, text) == QMessageBox.StandardButton.Yes

    def ask_sign_or_verify(self, name: str) -> str | None:
        box = QMessageBox(QMessageBox.Icon.Question, "Cosa vuoi fare?", f"Cosa vuoi fare con {name}?", parent=self)
        sign = box.addButton("Firmarlo", QMessageBox.ButtonRole.AcceptRole)
        check = box.addButton("Controllare la firma", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Annulla", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        return {sign: "firma", check: "verifica"}.get(box.clickedButton())

    def show_error(self, title: str, text: str) -> None:
        QMessageBox.warning(self, title, text)

    def run_setup(self, first_run: bool) -> bool:
        dialog = SetupDialog(self, lambda: self.api, first_run, self.profile)
        accepted = dialog.exec() == SetupDialog.DialogCode.Accepted
        if accepted:
            self.profile = dialog.profile
        self.home.refresh(self.profile)
        return accepted

    def open_url(self, path: Path) -> None:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    # --- navigation and drops ------------------------------------------------------------------

    @property
    def api(self):
        if self._api is None:
            self._api = self.api_factory()
        return self._api

    def go_home(self) -> None:
        self.home.refresh(self.profile)
        self.stack.setCurrentWidget(self.home)

    def _unlock_quietly(self) -> None:
        """Open the profile with the saved password, if there is one (to show the account name)."""
        try:
            password = credentials.stored_password()
            if password and vault.exists():
                self.profile = vault.load(password)
        except FirmaError as exc:
            log.info("profilo non aperto all'avvio: %s", exc.message)

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
        if len(paths) == 1 and paths[0].lower().endswith(".p7m"):
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

    def ensure_configured(self) -> bool:
        return vault.exists() or self.run_setup(first_run=True)

    def prepare_sign(self, paths: list[str], kind: Kind) -> None:
        if not self.ensure_configured():
            return
        self.paths = [Path(p) for p in paths]
        if kind is Kind.PADES:
            self.options.load(config.load(), self.paths)
            self.stack.setCurrentWidget(self.options)
        else:
            self.sign([SignJob(p, Kind.CADES) for p in self.paths])

    def options_confirmed(self) -> None:
        settings = config.load()
        self.options.save_to(settings)
        config.save(settings)
        spec = self.options.stamp_spec()
        self.sign([SignJob(p, Kind.PADES, spec) for p in self.paths])

    def unlock(self) -> tuple[str, vault.Profile] | None:
        """Password (wallet, or asked) and decrypted profile. A mistyped password fails here, locally."""
        store = None
        try:
            store = credentials.get_store()
            password = store.get(credentials.PASSWORD_KEY) if store else None
        except credentials.CredentialStoreError as exc:
            self.show_error("Portachiavi", exc.message)
            password = None
        remember = False
        if not password:
            answer = self.ask_password(store.name if store else None)
            if answer is None:
                return None
            password, remember = answer
        try:
            profile = vault.load(password)
        except FirmaError as exc:
            self.show_error("Password", exc.message)
            return None
        self.profile = profile
        # a typed password is saved only once Aruba has accepted it (when the signing session opens)
        self.pending_password = password if remember and store else None
        return password, profile

    def sign(self, jobs: list[SignJob]) -> None:
        problems = service.preflight(jobs)
        if problems:
            self.show_error("Impossibile firmare", "\n".join(problems) + "\n\nNon è stato usato nessun codice OTP.")
            return
        settings = config.load()
        unlocked = self.unlock()
        if unlocked is None:
            return
        password, profile = unlocked
        otp = self.ask_otp(len(jobs), service.auth_failures())
        if otp is None:
            return
        self.cancel_event = threading.Event()
        self.progress.start("Firma in corso...", total=len(jobs), cancellable=len(jobs) > 1)
        self.stack.setCurrentWidget(self.progress)
        job = worker.Worker(service.sign_batch, self.api, service.account_from(profile, settings), password, otp,
                            jobs, signer_name=profile.signer_name or None, cancel=self.cancel_event)
        job.kwargs["progress"] = job.report
        worker.start(self, job, self.sign_done, self.sign_failed, self.progress.update_progress)

    def sign_done(self, results: list[JobResult]) -> None:
        if self.pending_password:
            try:
                credentials.get_store().set(credentials.PASSWORD_KEY, self.pending_password)
            except (credentials.CredentialStoreError, AttributeError) as exc:
                log.warning("password non salvata: %s", exc)
            self.pending_password = None
        self.results = results
        self.result.show_results(results)
        self.stack.setCurrentWidget(self.result)

    def sign_failed(self, exc: Exception) -> None:
        self.pending_password = None
        self.go_home()
        self.show_error("Firma non riuscita", _error_text(exc))

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
        paths = self.choose_files("Scegli il file firmato", "File firmati (*.pdf *.p7m *.PDF *.P7M);;Tutti i file (*)",
                                  multiple=False)
        if paths:
            self.verify(paths[0])

    def verify(self, path: str) -> None:
        self.report_path, self.extracted = Path(path), None
        self.progress.start("Controllo della firma in corso...", total=None, cancellable=False)
        self.progress.current.setText("La prima volta può richiedere qualche secondo.")
        self.stack.setCurrentWidget(self.progress)
        worker.start(self, worker.Worker(verify.verify_file, self.report_path), self.verify_done, self.verify_failed)

    def verify_done(self, report: VerifyReport) -> None:
        self.report = report
        self.verify_page.show_report(report, self.report_path)
        self.stack.setCurrentWidget(self.verify_page)

    def verify_failed(self, exc: Exception) -> None:
        self.go_home()
        self.show_error("Controllo non riuscito", _error_text(exc))

    def open_verified_document(self) -> None:
        if self.report is None:
            return
        register_paths(self.report_path)
        if self.report.content is None:  # a signed PDF: open it as it is
            self.open_url(self.report_path)
            return
        if self.extracted is None:
            try:
                self.extracted = files.write_new(self.report_path.parent, self.report.content_name, self.report.content)
            except FileError as exc:
                self.show_error("Impossibile aprire il documento", exc.message)
                return
        self.open_url(self.extracted)

    # --- support -----------------------------------------------------------------------------

    def support(self) -> None:
        self.progress.start("Controllo in corso...", total=None, cancellable=False)
        self.stack.setCurrentWidget(self.progress)
        try:
            password = credentials.stored_password()
        except credentials.CredentialStoreError:
            password = None
        worker.start(self, worker.Worker(diagnostics.report, self.api, password), self.support_done, self.verify_failed)

    def support_done(self, lines) -> None:
        self.go_home()
        self.show_support(diagnostics.as_text(lines))

    def show_support(self, text: str) -> None:
        TextDialog(self, "Assistenza", "Se qualcosa non funziona, premi «Copia» e incolla queste informazioni "
                   "in un messaggio a chi ti aiuta. Non contengono la password.", text).exec()
