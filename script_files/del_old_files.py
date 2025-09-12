import os
import time
import sys
import shutil

# get current time
now = time.time()	

# get customer id from command line
cust_id = sys.argv[1]	

dir_list = [f'./report_files/{cust_id}',f'./database_files/{cust_id}',f'./source_files/{cust_id}']	

run_file = 'run.sh'


def get_retention_seconds(run_file):
	with open (run_file) as f: # Extract old_files_retention variable from run.sh
		for line in f:
		#find line starting with aipdb_key
			if line.startswith('delete_old_files_retention'):
				#print value after = sign
				
				retention_months = int(line.split('=')[1].replace('\n',''))
				continue

	#print(retention_months)
	retention_seconds = retention_months*2592000
	#print(retention_seconds)
				

	return retention_seconds


def delete_old_files():

	retention_seconds = get_retention_seconds(run_file)
	
	# loop through files
	for dir in dir_list:
		# get list of files in dir
		#check if dir exists
		if os.path.exists(dir):
			file_list = os.listdir(dir)
			# loop through files\
			for file in file_list:
				# print(file)
				

				file_ctime = os.path.getctime(dir+'/'+file) # get file creation time			
				file_mtime = os.path.getmtime(dir+'/'+file)	# get file last modified time

				# if file creation time  is older than X months OR  file modification time is older than X months, delete it
				if now - file_ctime > retention_seconds or now - file_mtime > retention_seconds:
					# check if file is a directory
					if os.path.isdir(dir+'/'+file):
						# delete directory
						#os.rmdir(dir+'/'+file)
						shutil.rmtree(dir+'/'+file)
						print(f"{dir+'/'+file} deleted")
					else:
						# delete file
						os.remove(dir+'/'+file)
						print(f"{dir+'/'+file} deleted")

if __name__ == "__main__":
	delete_old_files()






