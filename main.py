import os
import json
import base64
import sqlite3
import shutil
import json
from datetime import datetime, timedelta
import win32crypt  # pip install pypiwin32
from Crypto.Cipher import AES  # pip install pycryptodome


def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January, 1601"""
    if chromedate != 86400000000 and chromedate:
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
        except Exception as e:
            print(f"Error: {e}, chromedate: {chromedate}")
            return chromedate
    else:
        return ""


def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # decode the encryption key from Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # remove 'DPAPI' str
    key = key[5:]
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials
    # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def decrypt_data(data, key):
    try:
        # get the initialization vector
        iv = data[3:15]
        data = data[15:]
        # generate cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # decrypt password
        return cipher.decrypt(data)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(data, None, None, None, 0)[1])
        except:
            # not supported
            return ""


def get_domain_info():
    domain_name = '1'
    domain_query = input(
        "\nIn which domain do you want to search?\n1) All domains\n2) Manual domain\n\n").strip()
    if domain_query[0] == '1':
        return domain_name
    elif domain_query[0] == '2':
        domain_name = input("\nType the domain(e.g: google.com): ").strip()

        return domain_name
    else:
        print("Please select a valid option.")


def get_db_path_info():
    db_path_select_method = input(
        "Choose database path:\n1) Automatic\n2) Manual\n").strip()
    if db_path_select_method == '1':
        for i in range(15):
            try:
                db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                                       "Google", "Chrome", "User Data", f"Profile {i}", "Network", "Cookies")
                if os.path.exists(db_path):
                    print("Found database path.")
                    break
            except:
                pass
        if not db_path:
            raise Exception("Database path not found.")
        return db_path

    elif db_path_select_method == '2':
        return input("Type the full directory of your database(including db file).\n")


def main():

    # local sqlite Chrome cookie database path
    db_path = get_db_path_info()

    # copy the file to current directory
    # as the database will be locked if chrome is currently open
    filename = "Cookies.db"
    # start output file
    with open(f"{filename}.json", "w") as file:
        file.write("[")
    if not os.path.isfile(filename):
        # copy file when does not exist in the current directory
        shutil.copyfile(db_path, filename)

    # connect to the database
    db = sqlite3.connect(filename)
    # ignore decoding errors
    db.text_factory = lambda b: b.decode(errors="ignore")
    cursor = db.cursor()
    # get the cookies from `cookies` table
    domain_name = get_domain_info()
    if domain_name != '1':
        cursor.execute(f"""
        SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value
        FROM cookies
        WHERE host_key like '{domain_name}' """)
    else:
        cursor.execute("""
        SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value 
        FROM cookies""")
        # you can also search by domain, e.g thepythoncode.com
        # cursor.execute("""
        # SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value
        # FROM cookies
        # WHERE host_key like '%thepythoncode.com%'""")

    # get the AES key
    key = get_encryption_key()
    for host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value in cursor.fetchall():
        if not value:
            decrypted_value = decrypt_data(encrypted_value, key)
        else:
            # already decrypted
            decrypted_value = value

        # update the cookies table with the decrypted value
        # and make session cookie persistent
        cursor.execute("""
        UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999, is_persistent = 1, is_secure = 0
        WHERE host_key = ?
        AND name = ?""", (decrypted_value, host_key, name))
        dictData = {
            'Host': host_key,
            'Cookie name': name,
            'Cookie value (decrypted)': decrypted_value,
            'Creation datetime (UTC)': get_chrome_datetime(creation_utc),
            'Last access datetime (UTC)': get_chrome_datetime(last_access_utc),
            'Expires datetime (UTC)': get_chrome_datetime(expires_utc)
        }
        with open(f"{filename}.json", "a+") as file:
            file.write(json.dumps(str(dictData)))
            file.write(",\n\n")
    # remove last , of output file
    with open(f"{filename}.json", 'rb+') as file:
        file.seek(-5, 2)
        file.truncate()
    # close json output file
    with open(f"{filename}.json", "a+") as file:
        file.write("]")
    # commit changes
    db.commit()
    # close connection
    db.close()
    print(f"File {filename[:-3]}.json was saved in path {os.getcwd()}")


if __name__ == "__main__":
    main()
