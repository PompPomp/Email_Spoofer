import os
import sys
import subprocess

def check_for_prerequisites():
    # check if jq is downloaded
    result = subprocess.run(['dpkg', '-s', 'jq'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    if result.returncode == 1:
        os.system("sudo apt install jq")
    
    # check if smtp-email-spoofer is downloaded
    if not os.path.isdir("./smtp-email-spoofer-py"):
        print("Downloading required repository..")
        os.system("git clone https://github.com/mikechabot/smtp-email-spoofer-py.git")
    
check_for_prerequisites()



domain = input("Enter domain to search: ")

def spoof(username, password, attacker_email):
    
    # SPECIFY VICTIM EMAILS (support@cysecure.co cysecureco@outlook.com)
    victim_emails = "support@cysecure.co cysecureco@outlook.com"
    
    command = f"yes 2>/dev/null | python3 ./smtp-email-spoofer-py/spoof.py cli --username {username} --password {password} --host smtp-relay.brevo.com --port 587 --sender {attacker_email} --name {domain} --recipients {victim_emails} --subject 'AES Vulnerability Test' --filename ./smtp-email-spoofer-py/message_body.html"
            
    os.system(command)
    print("Hint: Check the spam folder..")
    
    
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
    username = input("Enter username: ")
    password = input("Enter password: ")
    
    # Craft email body
    if os.path.isfile(f"./email_lists/{domain}_emails.txt"):
    	os.system("echo 'This is a test for business email compromise vulnerability. If email can be received, it means that the sending domain name is vulnerable towards email impersonation.' > ./smtp-email-spoofer-py/message_body.html")
    	
    spoof(username, password, chosen_email)
    
    
    
def retrieve_domain_json(domain):
    api_key = input("Enter Hunter.io API key: ")
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
   
    
if os.path.isfile(f"./email_lists/{domain}_emails.txt"):
    print(f"=========== Email list for {domain} already exists =========== \nExecuting email spoofer...\n")
    email_spoofer(domain)
else:
    retrieve_domain_json(domain)




