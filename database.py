import sqlite3
import hashlib
import bcrypt  # This will be for hashing passwords
from datetime import datetime, timedelta

user_db_file_location = "database_file/users.db"
note_db_file_location = "database_file/notes.db"
image_db_file_location = "database_file/images.db"

TIMEOUT_DURATION = timedelta(minutes=5)
MAX_FAILED_ATTEMPTS = 3


def list_users():
    _conn = sqlite3.connect(user_db_file_location)
    _c = _conn.cursor()

    _c.execute("SELECT id FROM users;")
    result = [x[0] for x in _c.fetchall()]

    _conn.close()

    return result


def verify(id, pw):
    _conn = sqlite3.connect(user_db_file_location)
    _c = _conn.cursor()

    _c.execute("SELECT pw FROM users WHERE id = ?", (id,))
    user_record = _c.fetchone()

    if user_record is None:
        _conn.close()
        return "Invalid credentials."

    stored_pw = user_record[0]

    try:
        is_valid = bcrypt.checkpw(pw.encode(), stored_pw)
    except ValueError:
        _conn.close()
        return "Error: Invalid password format in database."

    _c.execute(
        "SELECT failed_attempts, last_attempt FROM login_attempts WHERE id = ?", (id,)
    )
    attempt_record = _c.fetchone()

    if is_valid and attempt_record:
        failed_attempts, last_attempt_str = attempt_record
        last_attempt = datetime.strptime(last_attempt_str, "%Y-%m-%d %H:%M:%S")
        time_since_last_attempt = datetime.now() - last_attempt

        if (
            failed_attempts >= MAX_FAILED_ATTEMPTS
            and time_since_last_attempt < TIMEOUT_DURATION
        ):
            is_valid = False

        else:
            _c.execute("DELETE FROM login_attempts WHERE id = ?", (id,))
            is_valid = True

    else:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if attempt_record:
            _c.execute(
                "UPDATE login_attempts SET failed_attempts = failed_attempts + 1, last_attempt = ? WHERE id = ?",
                (now_str, id),
            )
        else:
            _c.execute(
                "INSERT INTO login_attempts (id, failed_attempts, last_attempt) VALUES (?, 1, ?)",
                (id, now_str),
            )
        is_valid = False

    _conn.commit()
    _conn.close()

    return is_valid


def delete_user_from_db(id):
    _conn = sqlite3.connect(user_db_file_location)
    _c = _conn.cursor()
    _c.execute("DELETE FROM users WHERE id = ?;", (id))
    _conn.commit()
    _conn.close()

    # when we delete a user FROM database USERS, we also need to delete all his or her notes data FROM database NOTES
    _conn = sqlite3.connect(note_db_file_location)
    _c = _conn.cursor()
    _c.execute("DELETE FROM notes WHERE user = ?;", (id))
    _conn.commit()
    _conn.close()

    # when we delete a user FROM database USERS, we also need to
    # [1] delete all his or her images FROM image pool (done in app.py)
    # [2] delete all his or her images records FROM database IMAGES
    _conn = sqlite3.connect(image_db_file_location)
    _c = _conn.cursor()
    _c.execute("DELETE FROM images WHERE owner = ?;", (id))
    _conn.commit()
    _conn.close()


def add_user(id, pw, new_secret):
    _conn = sqlite3.connect(user_db_file_location)
    _c = _conn.cursor()

    # Run bcrypt hashing of password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(pw.encode(), salt)

    _c.execute(
        "INSERT INTO users values(?, ?, ?)",
        (id.upper(), hashed_password, new_secret),
    )

    _conn.commit()
    _conn.close()


def get_user_totp_secret(id):
    _conn = sqlite3.connect(user_db_file_location)
    _c = _conn.cursor()

    command = "SELECT secret FROM users WHERE id = '" + id.upper() + "';"
    _c.execute(command)
    result = _c.fetchone()[0]

    _conn.commit()
    _conn.close()

    return result


def read_note_from_db(id):
    _conn = sqlite3.connect(note_db_file_location)
    _c = _conn.cursor()

    command = (
        "SELECT note_id, timestamp, note FROM notes WHERE user = '" + id.upper() + "';"
    )
    _c.execute(command)
    result = _c.fetchall()

    _conn.commit()
    _conn.close()

    return result


def match_user_id_with_note_id(note_id):
    # Given the note id, confirm if the current user is the owner of the note which is being operated.
    _conn = sqlite3.connect(note_db_file_location)
    _c = _conn.cursor()

    command = "SELECT user FROM notes WHERE note_id = '" + note_id + "';"
    _c.execute(command)
    result = _c.fetchone()[0]

    _conn.commit()
    _conn.close()

    return result


def write_note_into_db(id, note_to_write):
    _conn = sqlite3.connect(note_db_file_location)
    _c = _conn.cursor()

    current_timestamp = str(datetime.datetime.now())
    _c.execute(
        "INSERT INTO notes values(?, ?, ?, ?)",
        (
            id.upper(),
            current_timestamp,
            note_to_write,
            hashlib.sha1((id.upper() + current_timestamp).encode()).hexdigest(),
        ),
    )

    _conn.commit()
    _conn.close()


def delete_note_from_db(note_id):
    _conn = sqlite3.connect(note_db_file_location)
    _c = _conn.cursor()

    _c.execute("DELETE FROM notes WHERE note_id = ?;", (note_id))

    _conn.commit()
    _conn.close()


def image_upload_record(uid, owner, image_name, timestamp):
    _conn = sqlite3.connect(image_db_file_location)
    _c = _conn.cursor()

    _c.execute(
        "INSERT INTO images VALUES (?, ?, ?, ?)", (uid, owner, image_name, timestamp)
    )

    _conn.commit()
    _conn.close()


def list_images_for_user(owner):
    _conn = sqlite3.connect(image_db_file_location)
    _c = _conn.cursor()

    command = "SELECT uid, timestamp, name FROM images WHERE owner = '{0}'".format(
        owner
    )
    _c.execute(command)
    result = _c.fetchall()

    _conn.commit()
    _conn.close()

    return result


def match_user_id_with_image_uid(image_uid):
    # Given the note id, confirm if the current user is the owner of the note which is being operated.
    _conn = sqlite3.connect(image_db_file_location)
    _c = _conn.cursor()

    command = "SELECT owner FROM images WHERE uid = '" + image_uid + "';"
    _c.execute(command)
    result = _c.fetchone()[0]

    _conn.commit()
    _conn.close()

    return result


def delete_image_from_db(image_uid):
    _conn = sqlite3.connect(image_db_file_location)
    _c = _conn.cursor()

    _c.execute("DELETE FROM images WHERE uid = ?;", (image_uid))

    _conn.commit()
    _conn.close()


if __name__ == "__main__":
    print(list_users())
