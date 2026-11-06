import secrets
import yara
import pefile
import psutil
import watchdog
import sys
import cpuinfo
import pynvml
import shutil
import webbrowser
import base64

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTextEdit, QLineEdit, QDialog,
    QDialogButtonBox, QMessageBox, QFileDialog, QGridLayout
)
from PyQt6.QtGui import QColor, QFont
from pathlib import Path
from datetime import datetime

CONFIG_FILE = Path(__file__).parent / "system_monitor_config.txt"
CREDENTIALS_FILE = Path(__file__).parent / "system_monitor_credentials.bin"
VERnam_KEY_FILE = Path(__file__).parent / "system_monitor_vernam.key"

password_encrypted: str | None = None
product_code_encrypted: str | None = None
admin_password_encrypted: str | None = None

def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key_byte for byte, key_byte in zip(data, key))

def vernam_encrypt(secret: str, key: bytes) -> str:
    secret_bytes = secret.encode("utf-8")

    if len(key) < len(secret_bytes):
        raise ValueError("Ключ Вернама короче шифруемого текста.")

    encrypted = xor_bytes(secret_bytes, key[:len(secret_bytes)])
    return base64.b64encode(encrypted).decode("ascii")

def vernam_decrypt(encrypted_base64: str, key: bytes) -> str:
    encrypted = base64.b64decode(encrypted_base64.encode("ascii"))

    if len(key) < len(encrypted):
        raise ValueError("Ключ Вернама короче зашифрованного текста.")

    decrypted = xor_bytes(encrypted, key[:len(encrypted)])
    return decrypted.decode("utf-8")


def create_vernam_key(length: int = 128) -> bytes:
    return secrets.token_bytes(length)


def save_vernam_key(key: bytes):
    VERnam_KEY_FILE.write_bytes(key)


def load_vernam_key() -> bytes | None:
    if not VERnam_KEY_FILE.exists():
        return None

    key = VERnam_KEY_FILE.read_bytes()

    if len(key) < 128:
        return None

    return key

def verify_vernam_secret(secret: str, encrypted_base64: str | None) -> bool:
    try:
        key = load_vernam_key()

        if key is None or not encrypted_base64:
            return False

        decrypted = vernam_decrypt(encrypted_base64, key)
        return secrets.compare_digest(secret, decrypted)

    except Exception:
        return False

def save_credentials(
    password_encrypted: str,
    product_code_encrypted: str,
    admin_password_encrypted: str,
):
    CREDENTIALS_FILE.write_text(
        f"{password_encrypted}\n"
        f"{product_code_encrypted}\n"
        f"{admin_password_encrypted}\n",
        encoding="utf-8"
    )

def change_credentials(
    admin_entered: str,
    new_password: str,
    new_product_code: str,
) -> tuple[bool, str]:
    global password_encrypted, product_code_encrypted, admin_password_encrypted

    try:
        if not verify_vernam_secret(admin_entered, admin_password_encrypted):
            return False, "Неверный администраторский пароль."

        if len(new_password) < 6:
            return False, "Новый пароль должен содержать не менее 6 символов."

        if len(new_product_code) < 8:
            return False, "Новый код продукта должен содержать не менее 8 символов."

        key = load_vernam_key()

        if key is None:
            return False, "Ключ шифрования не найден."

        new_password_encrypted = vernam_encrypt(new_password, key)
        new_product_code_encrypted = vernam_encrypt(new_product_code, key)

        save_credentials(
            new_password_encrypted,
            new_product_code_encrypted,
            admin_password_encrypted,
        )

        password_encrypted = new_password_encrypted
        product_code_encrypted = new_product_code_encrypted

        return True, "Пароль и код продукта успешно изменены."

    except Exception as error:
        return False, f"Не удалось изменить данные: {error}"

ADMIN_PASSWORD_FILE = CONFIG_FILE

class CreateCredentialsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Создание паролей")
        self.setMinimumWidth(480)

        self.password = ""
        self.product_code = ""
        self.admin_password = ""

        layout = QVBoxLayout(self)

        info = QLabel(
            "Придумай и введи данные для этой копии программы.\n"
            "Они будут зашифрованы шифром Вернама. Не удаляй и не передавай файл ключа."
        )
        info.setWordWrap(True)

        password_label = QLabel("Пароль для доступа (минимум 6 символов):")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        password_repeat_label = QLabel("Повтори пароль для доступа:")
        self.password_repeat_input = QLineEdit()
        self.password_repeat_input.setEchoMode(QLineEdit.EchoMode.Password)

        code_label = QLabel("Код продукта (минимум 8 символов):")
        self.code_input = QLineEdit()
        self.code_input.setEchoMode(QLineEdit.EchoMode.Password)

        code_repeat_label = QLabel("Повтори код продукта:")
        self.code_repeat_input = QLineEdit()
        self.code_repeat_input.setEchoMode(QLineEdit.EchoMode.Password)

        admin_label = QLabel("Администраторский пароль (минимум 8 символов):")
        self.admin_input = QLineEdit()
        self.admin_input.setEchoMode(QLineEdit.EchoMode.Password)

        admin_repeat_label = QLabel("Повтори администраторский пароль:")
        self.admin_repeat_input = QLineEdit()
        self.admin_repeat_input.setEchoMode(QLineEdit.EchoMode.Password)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.validate)
        buttons.rejected.connect(self.reject)

        for widget in (
            info,
            password_label, self.password_input,
            password_repeat_label, self.password_repeat_input,
            code_label, self.code_input,
            code_repeat_label, self.code_repeat_input,
            admin_label, self.admin_input,
            admin_repeat_label, self.admin_repeat_input,
            buttons,
        ):
            layout.addWidget(widget)

    def validate(self):
        password = self.password_input.text()
        password_repeat = self.password_repeat_input.text()
        product_code = self.code_input.text().strip()
        product_code_repeat = self.code_repeat_input.text().strip()
        admin_password = self.admin_input.text()
        admin_password_repeat = self.admin_repeat_input.text()

        if len(password) < 6:
            QMessageBox.warning(self, "Ошибка", "Пароль должен содержать минимум 6 символов.")
            return

        if password != password_repeat:
            QMessageBox.warning(self, "Ошибка", "Пароли не совпадают.")
            return

        if len(product_code) < 8:
            QMessageBox.warning(self, "Ошибка", "Код продукта должен содержать минимум 8 символов.")
            return

        if product_code != product_code_repeat:
            QMessageBox.warning(self, "Ошибка", "Коды продукта не совпадают.")
            return

        if len(admin_password) < 8:
            QMessageBox.warning(self, "Ошибка", "Администраторский пароль должен содержать минимум 8 символов.")
            return

        if admin_password != admin_password_repeat:
            QMessageBox.warning(self, "Ошибка", "Администраторские пароли не совпадают.")
            return

        self.password = password
        self.product_code = product_code
        self.admin_password = admin_password

        self.accept()

def load_or_create_credentials():
    global password_encrypted, product_code_encrypted, admin_password_encrypted

    key = load_vernam_key()

    if key is None:
        key = create_vernam_key(128)
        save_vernam_key(key)

    if CREDENTIALS_FILE.exists():
        lines = CREDENTIALS_FILE.read_text(encoding="utf-8").splitlines()

        password_encrypted = lines[0].strip() if len(lines) > 0 else ""
        product_code_encrypted = lines[1].strip() if len(lines) > 1 else ""
        admin_password_encrypted = lines[2].strip() if len(lines) > 2 else ""

        if password_encrypted and product_code_encrypted and admin_password_encrypted:
            return False

        CREDENTIALS_FILE.unlink(missing_ok=True)

    dialog = CreateCredentialsDialog()

    if dialog.exec() != QDialog.DialogCode.Accepted:
        sys.exit(0)

    password_encrypted = vernam_encrypt(dialog.password, key)
    product_code_encrypted = vernam_encrypt(dialog.product_code, key)
    admin_password_encrypted = vernam_encrypt(dialog.admin_password, key)

    save_credentials(
        password_encrypted,
        product_code_encrypted,
        admin_password_encrypted,
    )

    return True


first_run = False

class PasswordDialog(QDialog):
    def __init__(self, action_name, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Требуется пароль")
        self.setMinimumWidth(360)

        self.correct_password = False

        layout = QVBoxLayout(self)

        title = QLabel(f"Для выполнения «{action_name}» введите пароль:")
        title.setWordWrap(True)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Пароль")

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.check_password)
        buttons.rejected.connect(self.reject)

        layout.addWidget(title)
        layout.addWidget(self.password_input)
        layout.addWidget(buttons)

    def check_password(self):
        entered_password = self.password_input.text()

        try:
            is_correct = verify_vernam_secret(entered_password, password_encrypted)
        except Exception:
            is_correct = False

        if is_correct:
            self.correct_password = True
            self.accept()
        else:
            QMessageBox.warning(
                self,
                "Ошибка",
                "Неверный пароль."
            )
            self.password_input.clear()
            self.password_input.setFocus()


class ThreatActionDialog(QDialog):
    IGNORE = "ignore"
    QUARANTINE = "quarantine"
    DELETE = "delete"

    def __init__(self, file_path, rule_name, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Обнаружена угроза")
        self.setMinimumWidth(460)

        self.action = self.IGNORE

        layout = QVBoxLayout(self)

        warning = QLabel(
            f"Обнаружено возможное совпадение с правилом:\n"
            f"<b>{rule_name}</b><br><br>"
            f"Файл:<br><b>{file_path}</b>"
        )
        warning.setWordWrap(True)

        info = QLabel(
            "Выбери действие:\n"
            "• Игнорировать — оставить файл без изменений;\n"
            "• Карантин — переместить файл в папку карантина;\n"
            "• Удалить — безвозвратно удалить файл."
        )
        info.setWordWrap(True)

        ignore_button = QPushButton("Игнорировать")
        quarantine_button = QPushButton("Карантин")
        delete_button = QPushButton("Удалить")

        ignore_button.clicked.connect(lambda: self.choose_action(self.IGNORE))
        quarantine_button.clicked.connect(lambda: self.choose_action(self.QUARANTINE))
        delete_button.clicked.connect(self.confirm_delete)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(ignore_button)
        buttons_layout.addWidget(quarantine_button)
        buttons_layout.addWidget(delete_button)

        layout.addWidget(warning)
        layout.addWidget(info)
        layout.addLayout(buttons_layout)

    def choose_action(self, action):
        self.action = action
        self.accept()

    def confirm_delete(self):
        answer = QMessageBox.question(
            self,
            "Подтверждение удаления",
            "Файл будет удалён безвозвратно. Продолжить?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if answer == QMessageBox.StandardButton.Yes:
            self.action = self.DELETE


class SystemMonitorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Мониторинг системы")
        self.setMinimumSize(820, 620)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)

        title = QLabel("Мониторинг ПК")
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title)

        buttons_layout = QGridLayout()
        buttons_layout.setHorizontalSpacing(10)
        buttons_layout.setVerticalSpacing(10)

        self.cpu_model_button = QPushButton("Модель CPU")
        self.cpu_load_button = QPushButton("Нагрузка CPU")
        self.memory_button = QPushButton("Память ПК")
        self.process_memory_button = QPushButton("Память процесса")
        self.gpu_model_button = QPushButton("Модель GPU")
        self.gpu_state_button = QPushButton("Состояние GPU")
        self.virus_scan_button = QPushButton("Проверка на вирусы")
        self.disks_button = QPushButton("Диски")
        self.disk_activity_button = QPushButton("Активность дисков")
        self.product_code_button = QPushButton("Проверить код продукта")
        self.change_credentials_button = QPushButton("Изменить пароль и код")
        self.virus_info_button = QPushButton("Справка: Вирусы и защита")

        self.cpu_model_button.clicked.connect(lambda: self.run_protected_check("Модель CPU", self.check_cpu_model))
        self.cpu_load_button.clicked.connect(lambda: self.run_protected_check("Нагрузка CPU", self.check_cpu_load))
        self.memory_button.clicked.connect(lambda: self.run_protected_check("Память ПК", self.check_system_memory))
        self.process_memory_button.clicked.connect(
            lambda: self.run_protected_check("Память процесса", self.check_process_memory)
        )
        self.gpu_model_button.clicked.connect(lambda: self.run_protected_check("Модель GPU", self.check_gpu_model))
        self.gpu_state_button.clicked.connect(lambda: self.run_protected_check("Состояние GPU", self.check_gpu_state))
        self.virus_scan_button.clicked.connect(
            lambda: self.run_protected_check("Проверка на вирусы", self.check_viruses)
        )
        self.disks_button.clicked.connect(
            lambda: self.run_protected_check("Диски", self.check_disks)
        )
        self.disk_activity_button.clicked.connect(
            lambda: self.run_protected_check("Активность дисков", self.check_disk_activity)
        )
        self.product_code_button.clicked.connect(self.check_product_code)
        self.change_credentials_button.clicked.connect(self.change_credentials_dialog)
        self.virus_info_button.clicked.connect(self.open_virus_info_page)

        buttons = [
            self.cpu_model_button,
            self.cpu_load_button,
            self.memory_button,
            self.process_memory_button,
            self.gpu_model_button,
            self.gpu_state_button,
            self.disks_button,
            self.disk_activity_button,
            self.product_code_button,
            self.change_credentials_button
        ]

        for index, button in enumerate(buttons):
            row = index // 3
            column = index % 3
            button.setMinimumHeight(42)
            buttons_layout.addWidget(button, row, column)

        # 10 кнопок занимают строки 0-3; последняя ячейка строки 3 свободна
        self.virus_scan_button.setMinimumHeight(42)
        buttons_layout.addWidget(self.virus_scan_button, 3, 2, 1, 1)

        self.virus_info_button.setMinimumHeight(42)
        self.virus_info_button.setStyleSheet(
            "background-color: #17633e; border: 1px solid #2bb371;"
        )
        buttons_layout.addWidget(self.virus_info_button, 4, 0, 1, 3)

        buttons_layout.setColumnStretch(0, 1)
        buttons_layout.setColumnStretch(1, 1)
        buttons_layout.setColumnStretch(2, 1)

        main_layout.addLayout(buttons_layout)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 10))
        main_layout.addWidget(self.output)

        self.status_label = QLabel("Готово")
        main_layout.addWidget(self.status_label)

        self.setStyleSheet("""
            QWidget {
                background-color: #0f2540;
                color: #dce9f7;
                font-family: "Segoe UI";
                font-size: 10pt;
            }

            QPushButton {
                background-color: #1f4e79;
                color: #eaf2fb;
                border: 1px solid #3d80cc;
                border-radius: 6px;
                padding: 8px 14px;
                font-weight: 600;
            }

            QPushButton:hover {
                background-color: #2f6fb5;
            }

            QPushButton:pressed {
                background-color: #173a5e;
            }

            QTextEdit {
                background-color: #081827;
                color: #cfe3f7;
                border: 1px solid #2f6fb5;
                border-radius: 6px;
                padding: 8px;
            }

            QLabel {
                color: #9ec5e8;
                font-weight: 600;
            }
        """)

        self.setMinimumSize(860, 700) # Слегка увеличен размер по высоте под новую кнопку

    def open_virus_info_page(self):
        """Метод для открытия справочной статьи в браузере по умолчанию"""
        url = "https://pro32.com/ru/article/kakie-sushchestvuyut-vidy-kompyuternykh-virusov/"
        try:
            webbrowser.open(url)
            self.status_label.setText("Страница справки открыта в браузере")
        except Exception as error:
            QMessageBox.warning(self, "Ошибка", f"Не удалось открыть ссылку:\n{error}")

    def check_viruses(self):
        folder = QFileDialog.getExistingDirectory(
            self,
            "Выбери папку для проверки"
        )

        if not folder:
            return "Проверка отменена: папка не выбрана."

        rules = self.get_yara_rules()

        if rules is None:
            return "Проверка отменена: правила YARA недоступны."

        quarantine_dir = Path.home() / "SystemMonitorQuarantine"
        quarantine_dir.mkdir(exist_ok=True)

        folder_path = Path(folder)
        scanned_files = 0
        threats_found = 0

        result_lines = [
            "=== Проверка на вирусы ===",
            f"Папка: {folder_path}",
            f"Карантин: {quarantine_dir}",
            ""
        ]

        for file_path in folder_path.rglob("*"):
            if not file_path.is_file():
                continue

            try:
                scanned_files += 1
                matches = rules.match(str(file_path))
            except Exception as error:
                result_lines.append(f"Не удалось проверить: {file_path} — {error}")
                continue

            if not matches:
                continue

            for match in matches:
                threats_found += 1
                result_lines.append(
                    f"Обнаружено совпадение: {file_path}\n"
                    f"Правило: {match.rule}"
                )

                dialog = ThreatActionDialog(file_path, match.rule, self)
                dialog.exec()

                action = dialog.action

                if action == ThreatActionDialog.QUARANTINE:
                    quarantine_result = self.quarantine_file(file_path, quarantine_dir)
                    result_lines.append(quarantine_result)

                elif action == ThreatActionDialog.DELETE:
                    try:
                        file_path.unlink()
                        result_lines.append(f"Файл удалён: {file_path}")
                    except Exception as error:
                        result_lines.append(f"Не удалось удалить файл {file_path}: {error}")

                else:
                    result_lines.append(f"Файл проигнорирован: {file_path}")

                result_lines.append("-" * 50)

        result_lines.extend([
            "",
            f"Проверено файлов: {scanned_files}",
            f"Обнаружено совпадений: {threats_found}"
        ])

        return "\n".join(result_lines)

    def quarantine_file(self, file_path, quarantine_dir):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = file_path.name.replace(":", "_")
            destination = quarantine_dir / f"{timestamp}_{safe_name}"

            counter = 1

            while destination.exists():
                destination = quarantine_dir / f"{timestamp}_{counter}_{safe_name}"
                counter += 1

            shutil.move(str(file_path), str(destination))

            info_file = destination.with_suffix(destination.suffix + ".quarantine.txt")
            info_file.write_text(
                f"Исходный путь: {file_path}\n"
                f"Время карантина: {datetime.now()}\n",
                encoding="utf-8"
            )

            return f"Файл перемещён в карантин: {destination}"

        except Exception as error:
            return f"Не удалось переместить в карантин {file_path}: {error}"
    def run_protected_check(self, action_name, check_function):
        dialog = PasswordDialog(action_name, self)

        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.correct_password:
            self.status_label.setText(f"Выполняется: {action_name}...")
            QApplication.processEvents()

            try:
                result = check_function()
                self.output.append(result)
                self.output.append("=" * 70)
                self.status_label.setText(f"Готово: {action_name}")
            except Exception as error:
                self.output.append(f"Ошибка при выполнении «{action_name}»:\n{error}")
                self.status_label.setText("Ошибка")

    def check_cpu_model(self):
        info = cpuinfo.get_cpu_info()

        cpu_name = info.get("brand_raw", "Неизвестно")
        vendor = info.get("vendor_id_raw", "Неизвестно")
        architecture = info.get("arch", "Неизвестно")
        physical_cores = psutil.cpu_count(logical=False)
        logical_cores = psutil.cpu_count(logical=True)

        return "\n".join([
            "=== Процессор ===",
            f"Модель: {cpu_name}",
            f"Производитель: {vendor}",
            f"Архитектура: {architecture}",
            f"Физических ядер: {physical_cores}",
            f"Логических ядер: {logical_cores}"
        ])

    def check_cpu_load(self):
        cpu_percent = psutil.cpu_percent(interval=1)
        per_core = psutil.cpu_percent(interval=1, percpu=True)

        freq = psutil.cpu_freq()
        current_freq = f"{freq.current:.0f} MHz" if freq else "Недоступно"
        max_freq = f"{freq.max:.0f} MHz" if freq and freq.max else "Недоступно"

        lines = [
            "=== Нагрузка процессора ===",
            f"Общая загрузка CPU: {cpu_percent:.1f}%",
            f"Текущая частота: {current_freq}",
            f"Максимальная частота: {max_freq}",
            "Загрузка по ядрам:"
        ]

        for core, load in enumerate(per_core, start=1):
            lines.append(f"  Ядро {core}: {load:.1f}%")

        return "\n".join(lines)

    def check_system_memory(self):
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        return "\n".join([
            "=== Память ПК ===",
            f"Всего ОЗУ: {mem.total / (1024 ** 3):.2f} GB",
            f"Использовано: {mem.used / (1024 ** 3):.2f} GB",
            f"Доступно: {mem.available / (1024 ** 3):.2f} GB",
            f"Загрузка ОЗУ: {mem.percent:.1f}%",
            "",
            "=== Файл подкачки ===",
            f"Всего: {swap.total / (1024 ** 3):.2f} GB",
            f"Использовано: {swap.used / (1024 ** 3):.2f} GB",
            f"Свободно: {swap.free / (1024 ** 3):.2f} GB",
            f"Загрузка: {swap.percent:.1f}%"
        ])

    def check_disks(self):
        lines = ["=== Диски ==="]

        try:
            partitions = psutil.disk_partitions(all=False)
        except Exception as error:
            return f"Не удалось получить список дисков:\n{error}"

        if not partitions:
            return "Доступные диски не обнаружены."

        for index, partition in enumerate(partitions, start=1):
            mountpoint = partition.mountpoint
            device = partition.device
            filesystem = partition.fstype or "Неизвестно"
            options = partition.opts or "Неизвестно"

            lines.extend([
                f"Диск {index}:",
                f"Устройство: {device}",
                f"Точка монтирования: {mountpoint}",
                f"Файловая система: {filesystem}",
                f"Параметры монтирования: {options}"
            ])

            try:
                usage = psutil.disk_usage(mountpoint)

                total_gb = usage.total / (1024 ** 3)
                used_gb = usage.used / (1024 ** 3)
                free_gb = usage.free / (1024 ** 3)

                lines.extend([
                    f"Состояние: подключён и доступен",
                    f"Общий объём: {total_gb:.2f} GB",
                    f"Занято: {used_gb:.2f} GB ({usage.percent:.1f}%)",
                    f"Свободно: {free_gb:.2f} GB"
                ])

                if usage.percent >= 90:
                    lines.append("Предупреждение: занято 90% и более.")
                elif usage.percent >= 75:
                    lines.append("Внимание: занято 75% и более.")

            except PermissionError:
                lines.append("Состояние: раздел существует, но нет прав доступа для чтения статистики.")
            except OSError as error:
                lines.append(f"Состояние: недоступен ({error})")

            lines.append("-" * 50)

        lines.append("=== Активность дисков ===")

        try:
            io_stats = psutil.disk_io_counters(perdisk=True)

            if not io_stats:
                lines.append("Статистика I/O недоступна на этой системе.")
            else:
                for disk_name, stats in io_stats.items():
                    read_gb = stats.read_bytes / (1024 ** 3)
                    write_gb = stats.write_bytes / (1024 ** 3)

                    lines.extend([
                        f"Физический диск: {disk_name}",
                        f"Операций чтения: {stats.read_count}",
                        f"Операций записи: {stats.write_count}",
                        f"Прочитано: {read_gb:.2f} GB",
                        f"Записано: {write_gb:.2f} GB",
                        "-" * 30
                    ])

        except Exception as error:
            lines.append(f"Не удалось получить I/O-статистику:\n{error}")

        return "\n".join(lines)

    def check_disk_activity(self):
        """Проверяет количество прочитанных и записанных файлов (операций)
        и их объём на физических дисках."""
        lines = ["=== Активность дисков ==="]

        try:
            io_stats = psutil.disk_io_counters(perdisk=True)
        except Exception as error:
            return f"Не удалось получить I/O-статистику:\n{error}"

        if not io_stats:
            return "Статистика I/O недоступна на этой системе."

        for disk_name, stats in io_stats.items():
            read_gb = stats.read_bytes / (1024 ** 3)
            write_gb = stats.write_bytes / (1024 ** 3)
            read_mb = stats.read_bytes / (1024 ** 2)
            write_mb = stats.write_bytes / (1024 ** 2)

            lines.extend([
                f"Физический диск: {disk_name}",
                f"Операций чтения: {stats.read_count}",
                f"Операций записи: {stats.write_count}",
                f"Прочитано: {read_gb:.2f} GB ({read_mb:.1f} MB)",
                f"Записано: {write_gb:.2f} GB ({write_mb:.1f} MB)",
                "-" * 40
            ])

        return "\n".join(lines)

    def check_process_memory(self):
        process = psutil.Process()
        mem = process.memory_info()

        return "\n".join([
            "=== Память текущего процесса ===",
            f"RSS (физическая RAM): {mem.rss / (1024 ** 2):.2f} MB",
            f"VMS (виртуальная память): {mem.vms / (1024 ** 2):.2f} MB"
        ])

    def check_gpu_model(self):
        lines = ["=== Видеокарта ==="]

        try:
            pynvml.nvmlInit()
            device_count = pynvml.nvmlDeviceGetCount()

            if device_count == 0:
                return "NVIDIA-видеокарта не обнаружена."

            for i in range(device_count):
                handle = pynvml.nvmlDeviceGetHandleByIndex(i)

                name = self.decode_nvml_string(pynvml.nvmlDeviceGetName(handle))
                driver = self.decode_nvml_string(pynvml.nvmlSystemGetDriverVersion())
                uuid = self.decode_nvml_string(pynvml.nvmlDeviceGetUUID(handle))

                lines.extend([
                    f"Модель: {name}",
                    f"ID: {i}",
                    f"Драйвер: {driver}",
                    f"UUID: {uuid}",
                    "-" * 30
                ])

            return "\n".join(lines)

        except pynvml.NVMLError as error:
            return f"Не удалось получить данные видеокарты:\n{error}"
        finally:
            self.shutdown_nvml()

    def check_product_code(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Проверка кода продукта")
        dialog.setMinimumWidth(420)

        layout = QVBoxLayout(dialog)

        info = QLabel(
            "Введите код продукта для проверки.\n"
            "Код должен совпадать с кодом, выданным для этой копии программы."
        )
        info.setWordWrap(True)

        code_input = QLineEdit()
        code_input.setPlaceholderText("Код продукта")

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)

        layout.addWidget(info)
        layout.addWidget(code_input)
        layout.addWidget(buttons)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        entered_code = code_input.text().strip()

        if verify_vernam_secret(entered_code, product_code_encrypted):
            QMessageBox.information(
                self,
                "Код продукта",
                "Код продукта подтверждён."
            )
            self.output.append("=== Проверка кода продукта ===")
            self.output.append("Статус: код подтверждён")
            self.output.append("=" * 70)
        else:
            QMessageBox.warning(
                self,
                "Код продукта",
                "Неверный код продукта."
            )
            self.output.append("=== Проверка кода продукта ===")
            self.output.append("Статус: неверный код продукта")
            self.output.append("=" * 70)

    def change_credentials_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Изменение пароля и кода продукта")
        dialog.setMinimumWidth(460)

        layout = QVBoxLayout(dialog)

        admin_label = QLabel("Введите администраторский пароль:")
        admin_input = QLineEdit()
        admin_input.setEchoMode(QLineEdit.EchoMode.Password)
        admin_input.setPlaceholderText("Администраторский пароль")

        password_label = QLabel("Новый пароль:")
        password_input = QLineEdit()
        password_input.setEchoMode(QLineEdit.EchoMode.Password)
        password_input.setPlaceholderText("Минимум 8 символов")

        code_label = QLabel("Новый код продукта:")
        code_input = QLineEdit()
        code_input.setPlaceholderText("Минимум 8 символов")

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)

        for widget in (
                admin_label, admin_input,
                password_label, password_input,
                code_label, code_input,
                buttons,
        ):
            layout.addWidget(widget)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        admin_entered = admin_input.text()
        new_password = password_input.text()
        new_product_code = code_input.text().strip()

        try:
            success, message = change_credentials(
                admin_entered,
                new_password,
                new_product_code,
            )
        except Exception as error:
            success = False
            message = f"Непредвиденная ошибка: {error}"

        if success:
            QMessageBox.information(self, "Успешно", message)
            self.output.append("Пароль и код продукта изменены.")
            self.output.append("-" * 70)
        else:
            QMessageBox.warning(self, "Ошибка", message)
            self.output.append(f"Ошибка изменения данных: {message}")
            self.output.append("-" * 70)

    def get_yara_rules(self):
        rules_source = r'''
rule Suspicious_Batch_File
    {
        strings:
            $a = "powershell -enc" nocase
            $b = "certutil -urlcache" nocase
            $c = "bitsadmin /transfer" nocase

        condition:
            uint16(0) == 0x4550 or any of them
    }

    rule Suspicious_AutoRun
    {
        strings:
            $a = "[autorun]" nocase
            $b = "open=" nocase
            $c = "shellexecute=" nocase

        condition:
            all of them
    }

    rule Suspicious_Script_Keyword
    {
        strings:
            $a = "Invoke-Expression" nocase
            $b = "DownloadString" nocase
            $c = "Start-Process -Verb RunAs" nocase

        condition:
            any of them
    }
    '''

        try:
            return yara.compile(source=rules_source)
        except yara.Error as error:
            QMessageBox.critical(self, "Ошибка YARA", f"Не удалось скомпилировать правила:\n{error}")
            return None

    def check_gpu_state(self):
        lines = ["=== Состояние видеокарты ==="]

        try:
            pynvml.nvmlInit()
            device_count = pynvml.nvmlDeviceGetCount()

            if device_count == 0:
                return "Нет доступных NVIDIA GPU для мониторинга."

            for i in range(device_count):
                try:
                    handle = pynvml.nvmlDeviceGetHandleByIndex(i)

                    name = self.decode_nvml_string(pynvml.nvmlDeviceGetName(handle))
                    utilization = pynvml.nvmlDeviceGetUtilizationRates(handle)
                    memory = pynvml.nvmlDeviceGetMemoryInfo(handle)
                    temperature = pynvml.nvmlDeviceGetTemperature(
                        handle,
                        pynvml.NVML_TEMPERATURE_GPU
                    )

                    total_memory_mb = memory.total / (1024 ** 2)
                    used_memory_mb = memory.used / (1024 ** 2)
                    free_memory_mb = memory.free / (1024 ** 2)

                    if total_memory_mb > 0:
                        memory_percent = used_memory_mb / total_memory_mb * 100
                    else:
                        memory_percent = 0.0

                    lines.extend([
                        f"Видеокарта: {name}",
                        f"Загрузка GPU: {utilization.gpu:.1f}%",
                        f"Загрузка видеопамяти: {memory_percent:.1f}%",
                        f"Видеопамять: {used_memory_mb:.0f} MB из {total_memory_mb:.0f} MB",
                        f"Свободно: {free_memory_mb:.0f} MB",
                        f"Температура: {temperature} °C",
                        "-" * 30
                    ])

                except Exception as error:
                    lines.append(
                        f"Не удалось получить данные для GPU {i}: {error}"
                    )
                    lines.append("-" * 30)

            return "\n".join(lines)

        except Exception as error:
            return f"Не удалось получить состояние видеокарты:\n{error}"

        finally:
            self.shutdown_nvml()

    @staticmethod
    def decode_nvml_string(value):
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    @staticmethod
    def shutdown_nvml():
        try:
            pynvml.nvmlShutdown()
        except pynvml.NVMLError:
            pass

if __name__ == "__main__":
    app = QApplication(sys.argv)

    first_run = load_or_create_credentials()

    window = SystemMonitorApp()
    window.show()
    sys.exit(app.exec())