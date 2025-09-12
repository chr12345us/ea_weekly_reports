import smtplib
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email import encoders
from datetime import datetime
import sqlite3
import pandas as pd
import os
import sys
import tarfile

# sys.path.insert(0, './script_files')
# from epm_bar_chart import df as epm_bar_chart

cust_id = sys.argv[1]
#print(f'argv1 {cust_id}')

currentmonth = int(sys.argv[2]) #actual it will work on the previous month from today


currentyear = int(sys.argv[3])

smtp_auth = sys.argv[4]
if smtp_auth == "true":
        smtp_auth = True
else:
        smtp_auth = False

#print(smtp_auth)

smtp_server = sys.argv[5] # SMTP server name
#print(smtp_server)

smtp_server_port= sys.argv[6] # SMTP server port
#print(smtp_server_port)

smtp_sender = sys.argv[7] # Email sender address setting
#print(smtp_sender)

smtp_password = sys.argv[8] # Email password (optional)
#print(smtp_password)

smtp_list = sys.argv[10:] # Email address/address list recepient/s(comma separated)

smtp_subject_prefix = sys.argv[9] # Email Subject



##### Extract variables from run.sh ##############
run_file = 'run_daily.sh'
with open (run_file) as f:
    for line in f:
    #find line starting with top_n


        if line.startswith('report_range'):
            report_range = str(line.split('=')[1].replace('\n','').replace('"',''))
            continue

            
# Get the current date
current_date = datetime.now()

# Format the date as "Month, day, year"
today_formatted = current_date.strftime("%B, %d, %Y")



path_r = f'./report_files/{cust_id}/'
path_d = f'./database_files/{cust_id}/'






def archive_files(currentmonth):

        for root, dirs, files in os.walk(path_r):
                if root.split("/")[2] == cust_id:
                        for filename in files:
                                #attempt to split the file
                                try:
                                        if int(filename.split("_")[2]) == int(currentmonth) and int(filename.split("_")[3].split(".")[0]) == int(currentyear):
                                                if os.stat(os.path.join(root, filename)).st_size > 5000000: #if filesize > 5MB
                                                        if not filename.endswith(".tar.gz"):
                                                                # print(f'archiving {os.path.join(root, filename)}')
                                                                arcfile = os.path.join(root, filename) + '.tar.gz'
                                                                with tarfile.open(arcfile, "w:gz") as tar:
                                                                        tar.add(os.path.join(root, filename), arcname=os.path.basename(os.path.join(root, filename)))
                                except:
                                        print(f"Skipping file {filename} for archiving - not in the correct format")
                                        continue


def send_files(currentmonth,msg):
      for root, dirs, files in os.walk(path_r):
                if root.split("/")[2] == cust_id:
                        for filename in files:
                                try:
                                        if int(filename.split("_")[2]) == int(currentmonth) and int(filename.split("_")[3].split(".")[0]) == int(currentyear):
                                                if os.stat(os.path.join(root, filename)).st_size < 5000000:

                                                        #add condition if filename is not report_USCC_08_2023.htm
                                                        if filename !=f"report_{cust_id}_{currentmonth}_{currentyear}.htm" and filename !=f"report_{cust_id}_{currentmonth}_{currentyear}.txt":
                                                                
                                                                print(f'sending {os.path.join(root, filename)}')
                                                                attachment = open(os.path.join(root, filename), "rb")
                                                                p = MIMEBase('application', 'octet-stream')
                                                                p.set_payload((attachment).read())
                                                                encoders.encode_base64(p)
                                                                p.add_header('Content-Disposition', "attachment; filename= %s" % filename)
                                                                msg.attach(p)
                                                                attachment.close()
                                except:
                                        print(f"Skipping file {filename} from attaching to the email- not in the correct format")
                                        continue

def send_report(SMTP_AUTH,SMTP_SERVER,SMTP_SERVER_PORT,SMTP_SENDER,SMTP_PASSWORD,SMTP_LIST,SMTP_SUBJECT_PREFIX):

        msg = MIMEMultipart()
        msg["From"] = SMTP_SENDER
        msg["To"] = ', '.join(SMTP_LIST)

        #################################################### Attach files to the email ########################################################

        msg["Subject"] = SMTP_SUBJECT_PREFIX + f" Daily report  - {today_formatted}"
		
        archive_files(currentmonth)
        send_files(currentmonth ,msg)



        #######################################################################################################################################
 
        body = 'Daily report'
        msg.attach(MIMEText(body, 'html'))
        mailserver = smtplib.SMTP(host=SMTP_SERVER,port=SMTP_SERVER_PORT)
        mailserver.ehlo()
        if SMTP_AUTH:
                mailserver.starttls()
                mailserver.ehlo()
                mailserver.login(SMTP_SENDER, SMTP_PASSWORD)
        response = mailserver.sendmail(from_addr=SMTP_SENDER,to_addrs=SMTP_LIST, msg=msg.as_string())
        if response:
                print(f"Failed to deliver: {response}")  # Prints non-empty dict if issues
        else:
                print("Email sent successfully.")
        mailserver.quit()

send_report(smtp_auth,smtp_server,smtp_server_port,smtp_sender,smtp_password,smtp_list,smtp_subject_prefix)
