import os
import sys
import subprocess
import getpass

# https://stackoverflow.com/questions/73532164/proper-data-encryption-with-a-user-set-password-in-python3
import base64
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KDF_ALGORITHM = hashes.SHA256()
KDF_LENGTH = 32
KDF_ITERATIONS = 120000
credentials_path = "./credentials.txt"
api_key = "" 
domain = input("Enter domain to search: ")

def encrypt(plaintext: str, password: str) -> (bytes, bytes):
    # Derive a symmetric key using the passsword and a fresh random salt.
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=KDF_ALGORITHM, length=KDF_LENGTH, salt=salt,
        iterations=KDF_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))

    # Encrypt the message.
    f = Fernet(base64.urlsafe_b64encode(key))
    ciphertext = f.encrypt(plaintext.encode("utf-8"))

    return ciphertext, salt

def decrypt(ciphertext: bytes, password: str, salt: bytes) -> str:
    # Derive the symmetric key using the password and provided salt.
    kdf = PBKDF2HMAC(
        algorithm=KDF_ALGORITHM, length=KDF_LENGTH, salt=salt,
        iterations=KDF_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))

    # Decrypt the message
    f = Fernet(base64.urlsafe_b64encode(key))
    plaintext = f.decrypt(ciphertext)

    return plaintext.decode("utf-8")
    
    
def check_for_prerequisites():
    # check if jq is downloaded
    result = subprocess.run(['dpkg', '-s', 'jq'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    if result.returncode == 1:
        os.system("sudo apt install jq")
    
    # check if smtp-email-spoofer is downloaded
    if not os.path.isdir("./smtp-email-spoofer-py"):
        print("Downloading required repository..")
        os.system("git clone https://github.com/mikechabot/smtp-email-spoofer-py.git")


def main():
    check_for_prerequisites()
    if os.path.isfile(f"./email_lists/{domain}_emails.txt"):
        print(f"=========== Email list for {domain} already exists =========== \nExecuting email spoofer...\n")
        email_spoofer(domain)
    else:
        retrieve_domain_json(domain)

def save_session(username, password, api_key, smtp_server, port):
    save_session = input("Do you want to save your session? (Y/N): ")
    allowed_answers = ["Y", "N"]
    
    if save_session.upper() not in allowed_answers:
        print("Invalid input.. exiting program")
        sys.exit()
    
    if save_session.upper() == "Y" :
        session_pass = getpass.getpass("Enter a password for encryption: ")
        encrypted_password, salt_pass = encrypt(password, session_pass)
        encrypted_apikey, salt_api = encrypt(api_key, session_pass)
        
        with open(credentials_path, 'w') as file:
            file.write(username + "\n")
            file.write(encrypted_password.decode() + "\n")
            file.write(encrypted_apikey.decode() + "\n")
            file.write(smtp_server + "\n")
            file.write(port)
            
        with open('./salts', 'wb') as file:
            file.write(salt_pass)
            file.write(salt_api)
            
def read_from_save():
    
    session_pass = input("Enter session password: ")
    file = open(credentials_path)
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

    password = decrypt(str.encode(encrypted_pass), session_pass, salts[0])
    api_key = decrypt(str.encode(encrypted_apikey), session_pass, salts[1])
    return username, password, smtp_server, port, api_key

def spoof(attacker_email):
    if os.path.isfile(credentials_path):
        username, password, smtp_server, port = read_from_save()[0:4]
    else:
        username = input("Enter SMTP username: ")
        password = getpass.getpass("Enter SMTP password: ")
        # smtp-relay.brevo.com
        smtp_server = input("STMP server host: ")
        port = input("Enter port number: ")
    
    # SPECIFY VICTIM EMAILS (support@cysecure.co cysecureco@outlook.com)
    victim_emails = input("Enter victim emails to send to (Seperated by a space):")
    
    command = f"python3 ./smtp-email-spoofer-py/spoof.py cli --username {username} --password {password} --host {smtp_server} --port {port} --sender {attacker_email} --name {domain} --recipients {victim_emails} --subject 'AES Vulnerability Test' --filename ./smtp-email-spoofer-py/message_body.html"
    os.system(command)
    
    print("Email sent successfully. Check your inbox now.")
    print("Hint: Check the spam folder..")
    
    save_session(username, password, api_key, smtp_server, port)
    print("k")
    
def email_spoofer(domain):

    # Verify if github package is installed
    email_list = []
    file_path = f"./email_lists/{domain}_emails.txt"
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
            
        # Input validation 1
        except ValueError:
            print("Number pls")
            continue
            
    	# Input validation 2
        if not (0 < int(chosen_index) <= len(email_list)):
            print("Invalid index. Number does not exist")
            continue  # Skip the rest of the loop and start over
        else:
            executing = False
            
    chosen_email = email_list[chosen_index-1]

    # Craft email body
    if os.path.isfile(f"./email_lists/{domain}_emails.txt"):
    	os.system("echo 'This is a test for business email compromise vulnerability. If email can be received, it means that the sending domain name is vulnerable towards email impersonation.' > ./smtp-email-spoofer-py/message_body.html")
    	
    spoof(chosen_email)
    
    
def retrieve_domain_json(domain):

    if os.path.exists(credentials_path):
        api_key = read_from_save()[4]
    else:
        api_key = getpass.getpass("Enter Hunter.io API key: ")
    
    custom_url = "https://api.hunter.io/v2/domain-search?domain=" + domain + "&" + "api_key=" + api_key
    #GET_command = "curl " + custom_url + f" > {domain}_details.json"
    
    # write curl output into file
    json_file_path = f"./json_files/{domain}_details.json"
    os.makedirs(os.path.dirname(json_file_path), exist_ok=True)
    with open(json_file_path, 'w') as file:
    	output = subprocess.run(['curl', custom_url], stdout=file)

    # If domain is invalid
    if output.returncode == 3:
        print("Domain may be invalid")
        sys.exit()
    
    email_list_path = f"./email_lists/{domain}_emails.txt"
    os.makedirs(os.path.dirname(email_list_path), exist_ok=True)

    # Filter out emails from the json list
    os.system(f"jq -r '.data.emails[].value' ./json_files/{domain}_details.json > {email_list_path}")
    
    email_spoofer(domain)
   
    
main()



