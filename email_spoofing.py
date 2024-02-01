import os
import sys
import subprocess
import getpass
import base64
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EmailSpoofer:
    def __init__(self):
        self.KDF_ALGORITHM = hashes.SHA256()
        self.KDF_LENGTH = 32
        self.KDF_ITERATIONS = 120000
        self.api_key = ""
        self.save_exists = False
        self.credentials_path = "./credentials.txt"
        self.session_pass = ""

        # Get domain name
        while True:
            self.domain = input("Enter domain to search: ")
            if self.check_url_extension():
                break
            print("Enter a valid domain!")

        if os.path.exists(self.credentials_path):
            self.save_exists = True

    def check_url_extension(self):
        valid_extensions = [".com", ".sg", ".net"]
        url_without_params = self.domain.split('?')[0].split('#')[0]

        for extension in valid_extensions:
            if url_without_params.endswith(extension):
                return True
        return False

    def encrypt(self, plaintext: str, password: str) -> (bytes, bytes):

        salt = secrets.token_bytes(16)

        kdf = PBKDF2HMAC(
            algorithm=self.KDF_ALGORITHM, length=self.KDF_LENGTH, salt=salt,
            iterations=self.KDF_ITERATIONS)
        key = kdf.derive(password.encode("utf-8"))

        f = Fernet(base64.urlsafe_b64encode(key))
        ciphertext = f.encrypt(plaintext.encode("utf-8"))

        return ciphertext, salt

    def decrypt(self, ciphertext: bytes, password: str, salt: bytes) -> str:
        kdf = PBKDF2HMAC(
            algorithm=self.KDF_ALGORITHM, length=self.KDF_LENGTH, salt=salt,
            iterations=self.KDF_ITERATIONS)
        key = kdf.derive(password.encode("utf-8"))

        f = Fernet(base64.urlsafe_b64encode(key))
        plaintext = f.decrypt(ciphertext)
        return plaintext.decode("utf-8")

    def check_for_prerequisites(self):
        result = subprocess.run(['dpkg', '-s', 'jq'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result.returncode == 1:
            os.system("sudo apt install jq")

        if not os.path.isdir("./smtp-email-spoofer-py"):
            print("Downloading required repository..")
            os.system("git clone https://github.com/mikechabot/smtp-email-spoofer-py.git")

    def save_session(self, username, password, api_key, smtp_server, port):
        if self.save_exists:
            sys.exit()

        save_session = input("Do you want to save your session? (Y/N): ")
        allowed_answers = ["Y", "N"]
        if save_session.upper() not in allowed_answers:
            print("Invalid input.. exiting program")
            sys.exit()

        if save_session.upper() == "Y":
            self.session_pass = getpass.getpass("Enter a password for encryption: ")
            encrypted_password, salt_pass = self.encrypt(password, self.session_pass)
            encrypted_apikey, salt_api = self.encrypt(api_key, self.session_pass)

            api_key = self.decrypt(encrypted_apikey, self.session_pass, salt_api)

            with open(self.credentials_path, 'w') as file:
                file.write(username + "\n")
                file.write(encrypted_password.decode() + "\n")
                file.write(encrypted_apikey.decode() + "\n")
                file.write(smtp_server + "\n")
                file.write(port)

            salts = []
            with open('./salts', 'wb') as file:
                file.write(salt_pass)
                file.write(salt_api)

        print("Saved successfully.")

    def read_from_save(self):
        try:
            if self.session_pass == "":
                self.session_pass = getpass.getpass("Enter session password: ")

            file = open(self.credentials_path)
            content = file.readlines()

            username = content[0].rstrip('\n')
            encrypted_pass = content[1].rstrip('\n')
            encrypted_apikey = content[2].rstrip('\n')
            smtp_server = content[3].rstrip('\n')
            port = content[4]
            file.close()

            salts = []
            file = open('./salts', mode="rb")
            for i in range(2):
                salt = file.read(16)
                salts.append(salt)

            file.close()

            password = self.decrypt(str.encode(encrypted_pass), self.session_pass, salts[0])
            api_key = self.decrypt(str.encode(encrypted_apikey), self.session_pass, salts[1])

            return username, password, smtp_server, port, api_key

        except:
            print("Incorrect password")
            return

    def spoof(self, attacker_email):
        if self.save_exists:
            username, password, smtp_server, port = self.read_from_save()[0:4]
        else:
            username = input("Enter SMTP username: ")
            password = getpass.getpass("Enter SMTP password: ")
            smtp_server = input("STMP server host: ")
            port = input("Enter port number: ")

        victim_emails = input("Enter victim emails to send to (Seperated by a space): ")

        command = f"python3 ./smtp-email-spoofer-py/spoof.py cli --username {username} --password {password} --host {smtp_server} --port {port} --sender {attacker_email} --name {self.domain} --recipients {victim_emails} --subject 'AES Vulnerability Test' --filename ./smtp-email-spoofer-py/message_body.html"
        os.system(command)

        print("Executed.")
        print("Hint: Check the spam folder..")

        self.save_session(username, password, self.api_key, smtp_server, port)

    def email_spoofer(self):
        email_list = []
        file_path = f"./email_lists/{self.domain}_emails.txt"
        with open(file_path, 'r') as file:
            for line in file:
                email_list.append(line.rstrip('\n'))

        executing = True
        while executing:
            print("List of emails:")
            x = 1
            for email in email_list:
                print(f"[{x}] {email}")
                x += 1

            try:
                chosen_index = int(input("Select email (Enter index): "))
            except ValueError:
                print("Number pls")
                continue

            if not (0 < int(chosen_index) <= len(email_list)):
                print("Invalid index. Number does not exist")
                continue
            else:
                executing = False

        chosen_email = email_list[chosen_index - 1]

        if os.path.isfile(f"./email_lists/{self.domain}_emails.txt"):
            os.system(
                "echo 'This is a test for business email compromise vulnerability. If email can be received, it means that the sending domain name is vulnerable towards email impersonation.' > ./smtp-email-spoofer-py/message_body.html")

        self.spoof(chosen_email)

    def retrieve_domain_json(self):
        if self.save_exists:
            print("Detected previous save...")
            try:
                self.api_key = self.read_from_save()[4]
            except:
                self.api_key = getpass.getpass("Enter Hunter.io API key: ")

        else:
            self.api_key = getpass.getpass("Enter Hunter.io API key: ")

        custom_url = "https://api.hunter.io/v2/domain-search?domain=" + self.domain + "&" + "api_key=" + self.api_key

        json_file_path = f"./json_files/{self.domain}_details.json"

        os.makedirs(os.path.dirname(json_file_path), exist_ok=True)
        with open(json_file_path, 'w') as file:
            output = subprocess.run(['curl', custom_url], stdout=file)

        if output.returncode == 3:
            print("Domain may be invalid")
            sys.exit()

        email_list_path = f"./email_lists/{self.domain}_emails.txt"
        os.makedirs(os.path.dirname(email_list_path), exist_ok=True)

        os.system(f"jq -r '.data.emails[].value' ./json_files/{self.domain}_details.json > {email_list_path}")

        self.email_spoofer()


def main():
    email_spoofer = EmailSpoofer()
    email_spoofer.check_for_prerequisites()

    if os.path.isfile(f"./email_lists/{email_spoofer.domain}_emails.txt"):
        print(
            f"=========== Email list for {email_spoofer.domain} already exists =========== \nExecuting email spoofer...\n")
        email_spoofer.email_spoofer()
    else:
        email_spoofer.retrieve_domain_json()


if __name__ == "__main__":
    main()

