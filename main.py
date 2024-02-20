import sqlite3
import sys
import os
import csv
import string
import secrets
from datetime import datetime, timezone

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Protocol.KDF import PBKDF2

from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt, QTimer
from PyQt5.uic import loadUi
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTableWidgetItem, QMessageBox, QFileDialog, QLineEdit,
                             QHeaderView, QProgressBar)

UTC = datetime.now() - datetime.now(timezone.utc).replace(tzinfo=timezone.utc).replace(tzinfo=None)
VERSION = '1.0.4'
ENCRYPT_KEY = b''
SALT = b'5\x10\xf1%:\x8b\xfb<\xea\x8b)\xec\xfe\xaa\x0b\x1e\x88\xb2Xp\xf8P\xe8\xb4\xd38\xfa\x92\x08\x06\xde\xfd'


def toggle_show_password(window):
    if not window.show_password_buttons_states.get(window.sender())['shown']:
        window.sender().setIcon(QIcon('icons/opened_eye.png'))
        window.show_password_buttons_states[window.sender()]['line_edit'].setEchoMode(QLineEdit.Normal)
        window.show_password_buttons_states[window.sender()]['shown'] = True
    else:
        window.sender().setIcon(QIcon('icons/closed_eye.png'))
        window.show_password_buttons_states[window.sender()]['line_edit'].setEchoMode(QLineEdit.Password)
        window.show_password_buttons_states[window.sender()]['shown'] = False


def aes_gcm_encrypt(data: bytes) -> str:
    """
    GCM больше подходит для более частого шифрования большого объёма данных,
    так как он быстрее и может выполняться системой параллельно.
    """
    cipher = AES.new(ENCRYPT_KEY, AES.MODE_GCM)
    ciphered_data, tag = cipher.encrypt_and_digest(data)
    ciphered_data = get_full_cipher_in_hex(cipher.nonce, tag, ciphered_data)
    return ciphered_data


def aes_decrypt(ciphered_data: str, key: bytes, mode: str, decode=True) -> [str, bytes]:
    mode_dict = {'GCM': AES.MODE_GCM,
                 'EAX': AES.MODE_EAX}
    aes_mode = mode_dict[mode]

    read_nonce = bytes.fromhex(ciphered_data[:32])
    read_tag = bytes.fromhex(ciphered_data[32:64])
    read_ciphered_data = bytes.fromhex(ciphered_data[64:])

    cipher = AES.new(key, aes_mode, nonce=read_nonce)
    data = cipher.decrypt_and_verify(read_ciphered_data, read_tag)
    if decode:
        data = data.decode('utf-8')
    return data


def get_public_key_and_private_key_in_bytes() -> (bytes, bytes):
    key = RSA.generate(2048)
    public_key = key.publickey().export_key()
    private_key = key.export_key()
    return public_key, private_key


def get_full_cipher_in_hex(nonce: bytes, tag: bytes, key: bytes) -> str:
    """
    Форма хранения зашифрованного key и соответствующего tag и nonce в виде одной строки
    """
    nonce_hex = nonce.hex()
    tag_hex = tag.hex()
    key_hex = key.hex()
    full_key = nonce_hex + tag_hex + key_hex
    return full_key


def error_message_of_new_password_check(password: str, submit_password: str) -> (str | None):
    error_message = None

    if password != submit_password:
        error_message = 'Пароли не совпадают.'
    elif len(password) < 8:
        error_message = 'Пароль слишком короткий. Должно быть не менее 8 символов.'
    elif not any(letter.isupper() for letter in password):
        error_message = 'Пароль должен содержать хотя бы одну заглавную букву.'
    elif not any(letter.islower() for letter in password):
        error_message = 'Пароль должен содержать хотя бы одну строчную букву.'
    elif not any(letter.isdigit() for letter in password):
        error_message = 'Пароль должен содержать хотя бы одну цифру.'
    elif not any(not letter.isalnum() for letter in password):
        error_message = 'Пароль должен содержать хотя бы один специальный символ.'
    elif not password.isascii():
        error_message = 'Пароль должен содержать только латиницу.'

    return error_message


def message_box(text: str, title: str, kind='critical'):
    """
    QMessageBox
    """
    kinds = {
        'critical': QMessageBox.Critical,
        'information': QMessageBox.Information,
        'question': QMessageBox.Question,
        'warning': QMessageBox.Warning
    }

    msg_box = QMessageBox()
    msg_box.setWindowIcon(QIcon('icons/logo.png'))
    msg_box.setIcon(kinds[kind])
    msg_box.setText(text)
    msg_box.setWindowTitle(title)
    msg_box.exec_()


def save_to_history(cur, *ids: (int | list[int])):
    for account_id in ids:
        cur.execute("""INSERT INTO history (
                            id_ext,
                            service,
                            url,
                            login,
                            password,
                            deleted
                        )
                       SELECT id,
                              service,
                              url,
                              login,
                              password,
                              deleted
                       FROM accounts
                       WHERE id=?""", (account_id,))


class ChangeMasterPassword(QMainWindow):
    def __init__(self, parent):
        super().__init__(parent)
        loadUi('ui/change_master_password.ui', self)
        self.con = sqlite3.connect(self.parent().db_name)
        self.show_password_buttons_states = {
            self.showOldPasswordButton: {'shown': False,
                                         'line_edit': self.oldPasswordEdit},
            self.showNewPasswordButton: {'shown': False,
                                         'line_edit': self.newPasswordEdit},
            self.showNewPasswordSubmitButton: {'shown': False,
                                               'line_edit': self.newPasswordSubmitEdit}
        }

        self.setup_ui()

    def setup_ui(self):
        for button in self.show_password_buttons_states.keys():
            button.clicked.connect(lambda: toggle_show_password(self))
            self.show_password_buttons_states[button]['line_edit'].setEchoMode(QLineEdit.Password)

        self.buttonBox.accepted.connect(self.submit_master_password_change)
        self.buttonBox.rejected.connect(self.close)

    def submit_master_password_change(self):
        cur = self.con.cursor()
        old_password = self.oldPasswordEdit.text()
        new_password = self.newPasswordEdit.text()
        new_password_submit = self.newPasswordSubmitEdit.text()
        error_title = 'Смена пароля'

        if not all([old_password, new_password, new_password_submit]):
            message_box('Необходимо заполнить все поля!', error_title)
            return

        if old_password == new_password:
            message_box('Новый пароль должен отличаться!', error_title)
            return

        if new_password != new_password_submit:
            message_box('Пароли не совпадают!', error_title)
            return

        error_message = error_message_of_new_password_check(new_password, new_password_submit)
        if error_message:
            message_box(error_message, error_title)
            return

        try:
            ciphered_private_key = cur.execute("""SELECT value
                                                  FROM settings
                                                  WHERE name = 'ciphered_private_key'""").fetchone()[0]

            ciphered_encrypt_key = cur.execute("""SELECT value
                                                  FROM settings
                                                  WHERE name = 'ciphered_encrypt_key'""").fetchone()[0]

            if not ciphered_private_key or not ciphered_encrypt_key:
                msg_box = QMessageBox()
                msg_box.setIcon(QMessageBox.Critical)
                msg_box.setText("Нарушена целостность базы записей!")
                msg_box.setWindowTitle("Ошибка")
                msg_box.exec_()
                return

            unlock_key = PBKDF2(old_password, SALT, dkLen=32, count=100000)

            # Расшифровка ciphered_private_key с помощью unlock_key
            private_key = aes_decrypt(ciphered_private_key, unlock_key, 'EAX', decode=False)

            new_unlock_key = PBKDF2(new_password, SALT, dkLen=32, count=100000)

            # Шифруем private_key с помощью unlock_key
            cipher = AES.new(new_unlock_key, AES.MODE_EAX)
            ciphered_private_key, tag = cipher.encrypt_and_digest(private_key)

            # Форма хранения зашифрованного private_key и соответствующего tag и nonce в виде одной строки
            full_ciphered_private_key = get_full_cipher_in_hex(cipher.nonce, tag, ciphered_private_key)

            cur.execute("""UPDATE settings
                                SET value=?
                                WHERE name='ciphered_private_key'
                                """, (full_ciphered_private_key,))

            self.con.commit()

            message_box('Пароль изменён.', 'Смена мастер-пароля', 'information')

            self.close()

        except sqlite3.OperationalError:
            message_box('Нарушена целостность базы записей!', 'Проверка целостности')

        except UnicodeEncodeError:
            message_box('Пароли должны содержать только латиницу.', 'Проверка пароля')

        except Exception as error:
            error_text = str(error)
            error_title = 'Проверка пароля'

            if error_text == 'MAC check failed':
                error_text = 'Неправильный текущий пароль!'

            message_box(error_text, error_title)


class HelpWindow(QMainWindow):
    def __init__(self, parent):
        super().__init__(parent)
        loadUi('ui/help.ui', self)
        self.setup_ui()

    def setup_ui(self):
        self.buttonBox.accepted.connect(self.close)


class AddAccountDialog(QMainWindow):
    def __init__(self, parent, account_id=None, history_view=False):
        super().__init__(parent)
        loadUi('ui/add_account.ui', self)
        self.db_name = self.parent().db_name
        self.con = sqlite3.connect(self.parent().db_name)
        self.params = {}
        self.account_id = account_id
        self.history_view = history_view
        self.setup_ui()

    def setup_ui(self):
        tab_history_number = 1
        column_change_date = 1
        self.generatePasswordButton.clicked.connect(self.generate_password)
        self.generatePasswordButton.setIcon(QIcon('icons/shield.png'))
        self.tabWidget.currentChanged.connect(self.tab_changed)
        if self.account_id is not None:
            if not self.history_view:
                self.setWindowIcon(QIcon('icons/pencil.png'))
                self.setWindowTitle('Редактирование записи')
                self.buttonBox.accepted.connect(self.edit_elem)
                self.get_elem()
            else:
                self.tabWidget.setTabEnabled(tab_history_number, False)
                self.setWindowIcon(QIcon('icons/opened_eye.png'))
                self.setWindowTitle('Просмотр записи')
                self.generatePasswordButton.setEnabled(False)
                self.buttonBox.setEnabled(False)
                self.get_history_view_elem()
        else:
            self.tabWidget.setTabEnabled(tab_history_number, False)
            self.setWindowIcon(QIcon('icons/plus.png'))
            self.setWindowTitle('Добавление записи')
            self.buttonBox.accepted.connect(self.add_elem)
        self.buttonBox.rejected.connect(self.close)

        self.historyTable.doubleClicked.connect(self.double_clicked)
        history_header = self.historyTable.horizontalHeader()

        for column_number in range(6):
            if column_number == column_change_date:
                history_header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
            stretched_size = (self.historyTable.viewport().size().width()
                              - self.historyTable.horizontalHeader().sectionSize(0))
            size = max(self.historyTable.sizeHintForColumn(column_number), stretched_size)
            history_header.resizeSection(column_number, size)

    def double_clicked(self):
        rows = list(set([i.row() for i in self.historyTable.selectedItems()]))
        ids = [self.historyTable.item(i, 0).text() for i in rows]
        dialog = AddAccountDialog(self, account_id=ids[0], history_view=True)
        dialog.show()

    def generate_password(self):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        generated_password = ''.join(secrets.choice(alphabet) for _ in range(secrets.choice(range(15, 21))))
        self.passwordEdit.setText(generated_password)

    def get_elem(self):
        cur = self.con.cursor()
        item = cur.execute("""SELECT service, url, login, password
                                   FROM accounts
                                   WHERE id=?""", (self.account_id,)).fetchone()
        self.serviceEdit.setText(item[0])
        self.urlEdit.setText(item[1])
        self.loginEdit.setText(item[2])
        self.passwordEdit.setText(aes_decrypt(item[3], ENCRYPT_KEY, mode='GCM'))

    def get_history_view_elem(self):
        cur = self.con.cursor()
        item = cur.execute("""SELECT service, url, login, password
                                   FROM history
                                   WHERE id=?""", (self.account_id,)).fetchone()
        self.serviceEdit.setText(item[0])
        self.urlEdit.setText(item[1])
        self.loginEdit.setText(item[2])
        self.passwordEdit.setText(aes_decrypt(item[3], ENCRYPT_KEY, mode='GCM'))

    def add_elem(self):
        cur = self.con.cursor()
        try:
            new_data = (self.serviceEdit.text(),
                        self.urlEdit.text(),
                        self.loginEdit.text(),
                        aes_gcm_encrypt(self.passwordEdit.text().strip().encode('utf-8')))

            if not all([self.loginEdit.text(), self.passwordEdit.text()]):
                raise ValueError

            cur.execute("""INSERT INTO accounts(service, url, login, password, deleted)
                                VALUES (?,?,?,?,0)""", new_data)
        except (ValueError, Exception):
            message_box('Форма заполнена неверно.', 'Ошибка ввода', 'warning')
        else:
            self.con.commit()
            self.parent().update_accounts()
            self.close()

    def edit_elem(self):
        cur = self.con.cursor()
        try:
            save_to_history(cur, self.account_id)
            new_data = (self.serviceEdit.text(),
                        self.urlEdit.text(),
                        self.loginEdit.text(),
                        aes_gcm_encrypt(self.passwordEdit.text().strip().encode('utf-8')),
                        self.account_id)

            if not all([self.loginEdit.text(), self.passwordEdit.text()]):
                raise ValueError

            cur.execute("""UPDATE accounts
                                SET service=?, url=?, login=?, password=?
                                WHERE id=?""", new_data)
        except (ValueError, Exception):
            message_box('Форма заполнена неверно', 'Ошибка ввода', 'warning')
        else:
            self.con.commit()
            self.parent().update_accounts()
            self.close()

    def update_history(self):
        cur = self.con.cursor()
        que = """SELECT id, change_date, id_ext, service, url, login, password, deleted
                 FROM history
                 WHERE id_ext=?"""
        result = cur.execute(que, (self.account_id,)).fetchall()

        self.historyTable.setRowCount(len(result))
        try:
            self.historyTable.setColumnCount(len(result[0]))
            self.statusBar().clearMessage()
        except IndexError:
            self.statusBar().showMessage('Запись никак не изменялась!')

        column_change_date_number = 1
        column_deleted_number = 7

        for i, elem in enumerate(result):
            for j, val in enumerate(elem):
                if j == column_change_date_number:
                    timestamp_dt = datetime.strptime(val, "%Y-%m-%d %H:%M:%S")
                    val = timestamp_dt + UTC
                elif j == column_deleted_number:
                    val = 'Да' if val else 'Нет'
                self.historyTable.setItem(i, j, QTableWidgetItem(str(val)))

        for column_number in (0, 2):
            self.historyTable.setColumnHidden(column_number, True)

    def tab_changed(self, index):
        if index == 0:
            self.statusBar().clearMessage()
        if index == 1:
            self.update_history()


class MainWindow(QMainWindow):
    def __init__(self, db_name):
        super().__init__()
        loadUi('ui/main.ui', self)
        self.db_name = db_name
        self.con = sqlite3.connect(db_name)
        self.timer = QTimer()
        self.progressBar = QProgressBar(self)
        self.dialogue_opened = False
        self.selected_cell_in_password_column = False
        self.window = None
        self.clipboard_password = None
        self.buffer_timeout = None
        self.count = 0
        self.update_accounts()
        self.setup_ui()

    def setup_ui(self):
        cur = self.con.cursor()
        self.buffer_timeout = int(cur.execute("""SELECT value
                                                 FROM settings
                                                 WHERE name='buffer_timeout'""").fetchone()[0])

        self.progressBar.setValue(self.buffer_timeout)
        self.progressBar.hide()
        self.progressBar.setTextVisible(False)

        self.statusBar().addPermanentWidget(self.progressBar)
        self.progressBar.setMaximum(self.buffer_timeout)

        self.versionLabel.setText(f'Версия: {VERSION}')

        buttons_and_handlers = [
            (self.addAccountButton, self.add_account),
            (self.editAccountButton, self.edit_account),
            (self.deleteAccountButton, self.delete_account),
            (self.restoreAccountButton, self.restore_account),
            (self.deletePermanentlyButton, self.delete_permanently),
            (self.changeMasterPasswordButton, self.change_master_password),
            (self.saveBufferTimeoutButton, self.save_buffer_timeout)
        ]

        for button, handler in buttons_and_handlers:
            button.clicked.connect(handler)

        menu_and_handlers = [
            (self.createAction, self.create_database),
            (self.openAction, self.open_database),
            (self.csvAction, self.export_csv),
            (self.exitAction, self.close),
        ]

        for menu, handler in menu_and_handlers:
            menu.triggered.connect(handler)

        self.tabWidget.currentChanged.connect(self.tab_changed)
        self.userTable.doubleClicked.connect(self.double_clicked)
        self.userTable.cellPressed.connect(self.cell_pressed)
        self.timer.timeout.connect(self.on_timeout)
        self.bufferTimeoutSpinBox.valueChanged.connect(self.changed_buffer_timeout_value)

        self.searchEdit.textChanged.connect(self.update_accounts)
        self.searchEdit.addAction(QIcon('icons/loupe.png'), QLineEdit.ActionPosition.LeadingPosition)

        user_header = self.userTable.horizontalHeader()
        bin_header = self.binTable.horizontalHeader()

        for column_number in range(4):
            user_header.setSectionResizeMode(column_number, QHeaderView.Stretch)
            bin_header.setSectionResizeMode(column_number, QHeaderView.Stretch)

    def on_timeout(self):
        self.count += 1
        self.progressBar.setValue(self.buffer_timeout - self.count)
        self.statusBar().showMessage(f'Буфер обмена будет очищен через '
                                     f'{self.buffer_timeout - self.count} секунд.')
        if self.count == self.buffer_timeout:
            clipboard = QApplication.clipboard()
            clipboard.clear()
            self.count = 0
            self.progressBar.close()
            self.statusBar().clearMessage()
            self.progressBar.setValue(self.buffer_timeout)
            self.timer.stop()

    def cell_pressed(self, column, row):
        cell_cords = column, row
        if cell_cords[1] == 4:
            cell_id = self.userTable.item(column, 0).text()
            cur = self.con.cursor()
            item = cur.execute("""SELECT password
                                       FROM accounts
                                       WHERE id=?""", (cell_id,)).fetchone()
            self.clipboard_password = aes_decrypt(item[0], ENCRYPT_KEY, mode='GCM')
            self.selected_cell_in_password_column = True
        else:
            self.selected_cell_in_password_column = False

    def double_clicked(self):
        if self.selected_cell_in_password_column:
            text_to_copy = self.clipboard_password
            clipboard = QApplication.clipboard()
            clipboard.setText(text_to_copy)
            if self.progressBar.isVisible():
                self.count = -1
            else:
                self.progressBar.show()
                self.statusBar().showMessage(f'Буфер обмена будет очищен через {self.buffer_timeout} секунд.')
            self.timer.start(1000)
            message_box('Пароль скопирован.', 'Копирование пароля', kind='information')
        else:
            self.edit_account()

    def update_accounts(self):
        cur = self.con.cursor()
        search_req = self.searchEdit.text()

        if search_req:
            que = f"""SELECT id, service, url, login, password
                      FROM accounts
                      WHERE [service]||' '||[url]||' '||[login] LIKE ? AND deleted=0"""

            result = cur.execute(que, ('%' + search_req.strip() + '%',)).fetchall()
        else:
            que = """SELECT id, service, url, login, password
                     FROM accounts
                     WHERE deleted=0"""
            result = cur.execute(que).fetchall()

        self.userTable.setRowCount(len(result))
        try:
            self.userTable.setColumnCount(len(result[0]))
            self.statusBar().clearMessage()
        except IndexError:
            self.statusBar().showMessage('Нет записей!')

        for i, elem in enumerate(result):
            for j, val in enumerate(elem):
                self.userTable.setItem(i, j, QTableWidgetItem(str(val)))

        self.userTable.setColumnHidden(0, True)

    def update_bin(self):
        cur = self.con.cursor()
        que = """SELECT id, service, url, login, password
                 FROM accounts
                 WHERE deleted=1"""
        result = cur.execute(que).fetchall()

        self.binTable.setRowCount(len(result))
        try:
            self.binTable.setColumnCount(len(result[0]))
            self.statusBar().clearMessage()
        except IndexError:
            self.statusBar().showMessage('Корзина пуста!')

        for i, elem in enumerate(result):
            for j, val in enumerate(elem):
                self.binTable.setItem(i, j, QTableWidgetItem(str(val)))

        self.binTable.setColumnHidden(0, True)

    def add_account(self):
        dialog = AddAccountDialog(self)
        dialog.show()

    def edit_account(self):
        rows = list(set([i.row() for i in self.userTable.selectedItems()]))
        ids = [self.userTable.item(i, 0).text() for i in rows]
        if not ids:
            self.statusBar().showMessage('Ничего не выбрано')
            return
        else:
            self.statusBar().clearMessage()
        dialog = AddAccountDialog(self, account_id=ids[0])
        dialog.show()

    def delete_or_restore_accounts(self, table, is_delete):
        rows = list(set([i.row() for i in table.selectedItems()]))
        ids = [table.item(i, 0).text() for i in rows]

        if not ids:
            self.statusBar().showMessage('Ничего не выбрано')
            return
        else:
            self.statusBar().showMessage('')

        cur = self.con.cursor()
        save_to_history(cur, *ids)

        deleted_value = 1 if is_delete else 0
        cur.execute(f"""UPDATE accounts
                             SET deleted=?
                             WHERE id in ({', '.join('?' * len(ids))})""", [deleted_value] + ids)

        self.con.commit()

        if is_delete:
            self.update_accounts()
        else:
            self.update_bin()

    def delete_account(self):
        self.delete_or_restore_accounts(self.userTable, is_delete=True)

    def restore_account(self):
        self.delete_or_restore_accounts(self.binTable, is_delete=False)

    def changed_buffer_timeout_value(self):
        self.saveBufferTimeoutButton.setEnabled(True)

    def save_buffer_timeout(self):
        self.buffer_timeout = self.bufferTimeoutSpinBox.value()
        cur = self.con.cursor()
        cur.execute("""UPDATE settings
                            SET value=?
                            WHERE name='buffer_timeout'""", (self.buffer_timeout,))
        self.con.commit()
        self.progressBar.setValue(self.buffer_timeout)
        self.progressBar.setMaximum(self.buffer_timeout)
        self.saveBufferTimeoutButton.setEnabled(False)

    def delete_permanently(self):
        rows = list(set([i.row() for i in self.binTable.selectedItems()]))
        services = [self.binTable.item(i, 1).text() for i in rows]
        ids = [self.binTable.item(i, 0).text() for i in rows]
        if not ids:
            self.statusBar().showMessage('Ничего не выбрано')
            return
        else:
            self.statusBar().showMessage('')

        account_amount = 'запись'
        if len(ids) != 1:
            account_amount = 'записи'
        sep_between_accounts = '\n'

        valid = QMessageBox.question(self, 'Удаление записей из корзины',
                                     f"Вы действительно хотите удалить {account_amount}:\n"
                                     f"{sep_between_accounts.join(services)}?",
                                     QMessageBox.Yes,
                                     QMessageBox.No)

        if valid == QMessageBox.Yes:
            cur = self.con.cursor()
            cur.execute("PRAGMA foreign_keys = ON")
            cur.execute(f"""DELETE
                                 FROM accounts
                                 WHERE id in ({', '.join('?' * len(ids))})""", ids)
            self.con.commit()
            self.update_bin()

    def export_csv(self):
        cur = self.con.cursor()
        que = """SELECT service, login, url, password
                 FROM accounts
                 WHERE deleted=0"""
        result = cur.execute(que).fetchall()

        def decrypt_passwords(row):
            row = list(row)
            row[3] = aes_decrypt(row[3], ENCRYPT_KEY, mode='GCM')
            return row

        result = map(decrypt_passwords, result)

        options = QFileDialog.Options()

        csv_name, _ = QFileDialog.getSaveFileName(self, "Экспорт файла базы данных в CSV", "",
                                                  "Текстовый формат CSV (*.csv);;Все файлы (*)", options=options)

        if csv_name:
            with open(csv_name, 'w', newline='', encoding='utf-8') as csvfile:
                csv_writer = csv.writer(csvfile)
                csv_writer.writerow(['service', 'login', 'url', 'password'])
                csv_writer.writerows(result)

    def open_database(self):
        window = OpenOrCreateDatabaseWindow(self)
        window.open_database()

    def create_database(self):
        window = OpenOrCreateDatabaseWindow(self)
        window.open_database()

    def tab_changed(self, index):
        if index == 0:
            self.update_accounts()
        elif index == 1:
            self.update_bin()
        elif index == 2:
            self.statusBar().clearMessage()

    def change_master_password(self):
        dialog = ChangeMasterPassword(self)
        dialog.show()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_F1:
            window = HelpWindow(self)
            window.show()


class MasterPasswordWindow(QMainWindow):
    def __init__(self, db_name, is_new=False):
        super().__init__()
        if is_new:
            loadUi('ui/new_master_password.ui', self)
            self.show_password_buttons_states = {
                self.showPasswordButton: {'shown': False,
                                          'line_edit': self.passwordEdit},
                self.showSubmitPasswordButton: {'shown': False,
                                                'line_edit': self.submitPasswordEdit}
            }
        else:
            loadUi('ui/master_password.ui', self)
            self.show_password_buttons_states = {
                self.showPasswordButton: {'shown': False,
                                          'line_edit': self.passwordEdit}
            }
        self.db_name = db_name
        self.is_new = is_new
        self.show_password = False
        self.password_in_focus = True
        self.window = None
        self.password = None
        self.submit_password = None
        self.error_text = None
        self.error_title = None
        self.setup_ui()

    def setup_ui(self):
        self.showPasswordButton.clicked.connect(lambda: toggle_show_password(self))
        self.passwordEdit.setEchoMode(QLineEdit.Password)
        self.buttonBox.rejected.connect(self.open_or_create_database)

        if self.is_new:
            self.showSubmitPasswordButton.clicked.connect(lambda: toggle_show_password(self))
            self.submitPasswordEdit.setEchoMode(QLineEdit.Password)
            self.buttonBox.accepted.connect(self.submit_new_password)
            return

        self.setWindowTitle(f"База записей {self.db_name.split('/')[-1]}")
        self.buttonBox.accepted.connect(self.submit_existing_password)

        self.passwordEdit.installEventFilter(self)

    def eventFilter(self, source, event):
        if source is self.passwordEdit:
            if event.type() == event.FocusIn:
                self.password_in_focus = True
            elif event.type() == event.FocusOut:
                self.password_in_focus = False
        return super().eventFilter(source, event)

    def keyPressEvent(self, event):
        if self.password_in_focus:
            if event.key() == Qt.Key_Return:
                self.submit_existing_password()

    def submit_new_password(self):
        self.password = self.passwordEdit.text()
        self.submit_password = self.submitPasswordEdit.text()

        error_message = error_message_of_new_password_check(self.password, self.submit_password)

        self.submit_new_password_message(error_message)

    def submit_existing_password(self):
        self.password = self.passwordEdit.text()
        self.open_database()

    def submit_new_password_message(self, message):
        if message:
            message_box(message, 'Новый пароль')
            return

        self.create_database(self.password)

    def open_database(self):
        global ENCRYPT_KEY

        con = sqlite3.connect(self.db_name)
        cur = con.cursor()

        try:
            ciphered_private_key = cur.execute("""SELECT value
                                                  FROM settings
                                                  WHERE name = 'ciphered_private_key'
                                                  """).fetchone()[0]

            ciphered_encrypt_key = cur.execute("""SELECT value
                                                  FROM settings
                                                  WHERE name = 'ciphered_encrypt_key'
                                                  """).fetchone()[0]

            if not ciphered_private_key or not ciphered_encrypt_key:
                message_box('Нарушена целостность базы записей!', 'Ошибка')
                return

            unlock_key = PBKDF2(self.password, SALT, dkLen=32, count=100000)

            private_key = aes_decrypt(ciphered_private_key, unlock_key, 'EAX', decode=False)

            # Расшифровка encrypt_key с помощью private_key
            cipher = PKCS1_OAEP.new(RSA.importKey(private_key))
            ENCRYPT_KEY = cipher.decrypt(bytes.fromhex(ciphered_encrypt_key))

            self.window = MainWindow(self.db_name)
            self.window.show()
            self.close()

        except sqlite3.OperationalError:
            message_box('Нарушена целостность базы записей!', 'Проверка целостности')

        except UnicodeEncodeError:
            message_box('Пароль должен содержать только латиницу.', 'Проверка пароля')

        except Exception as error:
            error_text = str(error)
            error_title = 'Проверка пароля'

            if error_text == 'MAC check failed':
                error_text = 'Неправильный пароль!'

            message_box(error_text, error_title)

    def create_database(self, master_password):
        global ENCRYPT_KEY

        try:
            if os.path.exists(self.db_name):
                os.remove(self.db_name)

            con = sqlite3.connect(self.db_name)
            cur = con.cursor()

            # Создание таблиц со значениями
            cur.execute("""CREATE TABLE accounts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE,
                        service VARCHAR,
                        url VARCHAR,
                        login VARCHAR,
                        password VARCHAR,
                        deleted BOOLEAN DEFAULT (0)
                        )""")

            cur.execute("""CREATE TABLE settings (
                        name VARCHAR PRIMARY KEY NOT NULL UNIQUE,
                        value TEXT
                        )""")

            cur.execute("""CREATE TABLE history (
                           id INTEGER  PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,
                           change_date DATETIME NOT NULL DEFAULT (CURRENT_TIMESTAMP),
                           id_ext INTEGER NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
                           service VARCHAR,
                           url VARCHAR,
                           login VARCHAR,
                           password VARCHAR,
                           deleted BOOLEAN
                           )""")

            # Генерируем encrypt_key
            ENCRYPT_KEY = os.urandom(32)

            # Генерируем public_key и private_key
            public_key, private_key = get_public_key_and_private_key_in_bytes()
            public_key_in_hex = public_key.hex()

            unlock_key = PBKDF2(master_password, SALT, dkLen=32, count=100000)

            # Шифруем private_key с помощью unlock_key
            cipher = AES.new(unlock_key, AES.MODE_EAX)
            ciphered_private_key, tag = cipher.encrypt_and_digest(private_key)

            # Форма хранения зашифрованного private_key и соответствующего tag и nonce в виде одной строки
            full_ciphered_private_key = get_full_cipher_in_hex(cipher.nonce, tag, ciphered_private_key)

            # Шифровка encrypt_key открытым ключом public_key
            cipher = PKCS1_OAEP.new(RSA.importKey(public_key))
            ciphered_encrypt_key = cipher.encrypt(ENCRYPT_KEY)
            ciphered_encrypt_key_in_hex = ciphered_encrypt_key.hex()

            # Записываем служебные данные
            setting_data = (('buffer_timeout', 12),
                            ('version', VERSION),
                            ('public_key', public_key_in_hex),
                            ('ciphered_private_key', full_ciphered_private_key),
                            ('ciphered_encrypt_key', ciphered_encrypt_key_in_hex))

            for setting_row in setting_data:
                cur.execute("""INSERT INTO settings
                                    VALUES (?,?)""", setting_row)

            example_account_data = {'service': 'Яндекс',
                                    'url': 'yandex.ru',
                                    'login': 'Vanya502',
                                    'password': 'Тестовый пароль!@#'}

            # Шифровка пароля с помощью enc_key
            example_account_data['password'] = aes_gcm_encrypt(example_account_data['password'].encode('utf-8'))

            # Записываем пример записи
            cur.execute("""INSERT INTO accounts(service, url, login, password)
                                VALUES (?,?,?,?)""",
                        (example_account_data['service'],
                         example_account_data['url'],
                         example_account_data['login'],
                         example_account_data['password']))

            con.commit()

            self.window = MainWindow(self.db_name)
            self.window.show()
            self.close()

        except PermissionError:
            message_box('Этот файл занят другим процессом!', 'Другой процесс')
        except Exception as error:
            message_box(str(error), 'Ошибка')

    def open_or_create_database(self):
        self.window = OpenOrCreateDatabaseWindow()
        self.window.show()
        self.close()


class OpenOrCreateDatabaseWindow(QMainWindow):
    def __init__(self, parent=None):
        if parent:
            super().__init__(parent)
        else:
            super().__init__()

        loadUi('ui/open_or_create_db.ui', self)
        self.con = None
        self.window = None
        self.setup_ui()

    def setup_ui(self):
        self.openButton.setIcon(QIcon('icons/folder.png'))
        self.createButton.setIcon(QIcon('icons/document.png'))
        self.openButton.clicked.connect(self.open_database)
        self.createButton.clicked.connect(self.create_database)

    def open_database(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly

        db_name, _ = QFileDialog.getOpenFileName(self, "Открыть базу данных", "",
                                                 "База данных SQLite (*.db *.sqlite);;Все файлы (*)", options=options)

        if db_name:
            if self.parent():
                self.parent().close()
            self.window = MasterPasswordWindow(db_name)
            self.window.show()
            self.close()

    def create_database(self):
        options = QFileDialog.Options()

        db_name, _ = QFileDialog.getSaveFileName(self, "Создать новый файл базы данных", "",
                                                 "База данных SQLite (*.db *.sqlite);;Все файлы (*)", options=options)

        if db_name:
            if self.parent():
                self.parent().close()
            self.window = MasterPasswordWindow(db_name, is_new=True)
            self.window.show()
            self.close()


def except_hook(cls, exception, traceback):
    # Отлавливание исключений
    sys.__excepthook__(cls, exception, traceback)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    form = OpenOrCreateDatabaseWindow()
    form.show()
    sys.excepthook = except_hook
    sys.exit(app.exec())
