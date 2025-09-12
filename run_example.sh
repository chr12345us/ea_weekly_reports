#!/bin/bash

#-------------------------------------------
# PHP code by Marcelo Dantas
# Bash orchestration, dockerization, python - by Egor Egorov
#-------------------------------------------

current_date_time=$(date +"%Y-%m-%d %H:%M:%S")
echo "Current Date and Time: $current_date_time"
###################### Mandatory variables #########################################################
cust_list=(Customer-name)	#space separated list of customer IDs, do not use underscores

####################################################################################################

##################### Report Range #################################################################

cur_day=$(date +'%d')

cur_month=$(date +'%m') # This sets the month to the current month by default, so the data will be collected and report will be generatd for the previous $report_range. If the data needs to be collected for the different month, set the numberic value. For example if set to 4 (April), the script will collect and generate report for March.
# cur_month=3
cur_year=$(date +%Y)
# cur_year=2024
prev_year=$(expr $cur_year - 1)

if [[ "$cur_month" != 01 ]] && [ "$cur_month" != 1 ]; then
	prev_month=$(expr $cur_month - 1)

else
	prev_month=12
fi

if (( "$cur_month" >= 1 && "$cur_month" <= 9 )); then
    # Add a leading zero if the number is between 1 and 9
    cur_month=$(printf "%02d" "$cur_month")
    #echo "Formatted current month: $cur_month"
fi

if (( "$prev_month" >= 1 && "$prev_month" <= 9 )); then
    # Add a leading zero if the number is between 1 and 9
    prev_month=$(printf "%02d" "$prev_month")
    #echo "Formatted Prev month: $prev_month"
fi

abuseipdb=true
abuseipdb_key="xxxx"
#This variable is needed to fetch the information about top 10 malicious IP addresses from abuseipdb.com.
#Register and obtain your API key from https://www.abuseipdb.com/account/api

delete_old_files_retention=6
#Number of months to keep the old files. For example if set to 6, the script will delete all files older than 6 months.

top_n=7
#Number of top N items to be displayed in the report. For example if set to 10, the script will display top 10 items in the report.


####################################################################################################

######################## Convert Forensics(optional) ############################################################
convert_forensics_to_sqlite=false
forensics_file_cust_id="CustomerName"
forensics_date_format="%m.%d.%Y %I:%M:%S %p"
#forensic_date_format options: 
#'%m.%d.%Y %I:%M:%S %p',     # Format with 12-hour time
#'%m.%d.%Y %H:%M:%S',        # Format with 24-hour time
#'%d.%m.%Y %I:%M:%S %p',     # Alternate day-month order with 12-hour time
#'%d.%m.%Y %H:%M:%S'         # Alternate day-month order with 24-hour time
# Note, if date includes timezone(example 04.03.2024 8:00:11 PM EDT), remove it in csv before so it will be (04.03.2024 8:00:11 PM). In this case '%m.%d.%Y %I:%M:%S %p' format can be used
forensics_file_name="1_week_2023-11-27_15-53-20.csv"
converted_sqlite_file_name="database_CUSTID_10.sqlite"

#######################Action variables switch on/off(optional)####################################################

del_old_files=true
collect_data=true
gen_python_csv_data=true #generate csv data using python scripts
modify_csv=true
generate_report=true
generate_appendix=true
db_from_forensics=false
analyze_trends=true
email_send=true
####################################################################################################


####################### Email set up parameters for sending email with reports######################
smtp_auth=true
smtp_server="smtp.server.com" # SMTP server name
smtp_server_port=25 # SMTP server port
smtp_sender="sender_email@email.com" # Email sender address setting
smtp_password="smtp_password"  #Email password (optional)
smtp_list=(user1@mail.com user2@mail.com) #space separated list of email addresses		
####################################################################################################



#######################Proxy variables (optional) ##############################################################
is_http_proxy=false
is_https_proxy=false

is_proxy_for_email=false

http_proxy="proxyserver.com:3128"
https_proxy="proxyserver.com:3128"
####################################################################################################





#if directory source_files,database_files,report_files does not exist, create it
if [ ! -d "source_files" ]; then
  mkdir source_files
fi

if [ ! -d "database_files" ]; then
  mkdir database_files
fi

if [ ! -d "report_files" ]; then
  mkdir report_files
fi

#change directory to app
cd app 


################# Convert forensics to sqlite database #########################
if [ $convert_forensics_to_sqlite == "true" ]; then
	echo "Converting Forensics file to sqlite database"
	python3 script_files/forensics_to_sqlite.py $forensics_file_cust_id
fi

################# Collect data from Vision (must be here before setting proxy) ############################
for cust_id in "${cust_list[@]}"
do
	if [ $collect_data == "true" ]; then
		echo "Collecting Data from Vision"
		python3 script_files/collector.py $cust_id monthly $cur_month $cur_day $cur_year
	fi
done


################# Set Proxy ##########################################################################

if [ $is_https_proxy == "true" ]; then
	echo "Setting HTTPS Proxy"	

	export https_proxy="$https_proxy"
fi

if [ $is_http_proxy == "true" ]; then
	echo "Setting HTTP Proxy"
	export http_proxy="$http_proxy"
fi	


###Loop through customer list, delete old files, generate appendixes ###################################
for cust_id in "${cust_list[@]}"
do

	####################### Delete old files #################################

	if [[ "$del_old_files" == "true" ]]; then
		echo "Deleting old files"
		python3 script_files/del_old_files.py $cust_id #Delete old files
	fi

	####################### Generate CSV Data #################################


	if [[ $gen_python_csv_data == "true" ]]; then
	
		if [[ "$cur_month" == 1 ]] || [ "$cur_month" == 01 ]; then # Now is January case
			echo "Generating csv data for $prev_month $prev_year"
			python3 script_files/charts_and_tables.py $cust_id $prev_month $prev_year #this will generate csv for the previouis month
		else
			# Non January case
			echo "Generating csv data for $prev_month $cur_year"
			python3 script_files/charts_and_tables.py $cust_id $prev_month $cur_year #this will generate csv for the previouis month
		fi	

	fi


	####################### Modify CSV Data #################################
	
	
	if [ $modify_csv == "true" ]; then
		echo "Modifying csv data"
		python3 script_files/delete_column_csv.py $cust_id 
		echo "csv data modified"
	fi
	####################### Generate Report PDF #################################

	if [ $generate_report == "true" ]; then

		if [[ "$cur_month" != 01 ]] && [ "$cur_month" != 1 ]; then
			echo "Generating report for $prev_month $cur_year"
			php reportAll.php -- -month="$prev_month" -year="$cur_year" -id="$cust_id" #Generate and compile report to pdf
		else
			echo "Generating report for $prev_month $prev_year"
			php reportAll.php -- -month="$prev_month" -year="$prev_year" -id="$cust_id" #Generate and compile report to pdf
		fi
	fi


	####################### Generate Appendix #################################

	if [[ "$cur_month" != 01 ]] || [ "$cur_month" != 1 ]; then

		if [ $generate_appendix == "true" ]; then
			echo "Generating appendix for $prev_month $cur_year"
			python3 script_files/data_parser_to_appendix.py $cust_id $prev_month $cur_year #this will generate appendix for the previouis month
		fi

	else
		if [ $generate_appendix == "true" ]; then
			echo "Generating appendix for $prev_month $prev_year"
			python3 script_files/data_parser_to_appendix.py $cust_id $prev_month $prev_year #this will generate appendix for the previouis month
		fi
	fi

	######################### Analyze Trends ######################

	if [[ "$analyze_trends" == "true" ]]; then
	
			if [[ "$cur_month" == 1 ]] || [ "$cur_month" == 01 ]; then # Case for the month of January
				echo "Analyzing trends for $prev_month $prev_year"
				python3 script_files/analyze_trends.py $cust_id $prev_month $prev_year #this will generate trends for the previouis month
			else
				# Case if current month is not January
				echo "Analyzing trends for $prev_month $cur_year"
				python3 script_files/analyze_trends.py $cust_id $prev_month $cur_year #this will generate trends for the previouis month
			fi
	fi
	
done


################# Send email ##########################################################################
for cust_id in "${cust_list[@]}"
do
	smtp_subject_prefix="$cust_id" # Email Subject
	if [[ "$cur_month" != 01 ]] && [ "$cur_month" != 1 ]; then
		# Case for current month except January
		if [ $is_proxy_for_email == "true" ]; then
			# if variable is_proxy_for_email is set to true, then proxy will be set for email sending
			if [ $email_send == "true" ]; then
				echo "Sending email using proxy"
				python3 script_files/email_send.py $cust_id $prev_month $cur_year $smtp_auth $smtp_server $smtp_server_port $smtp_sender $smtp_password $smtp_subject_prefix ${smtp_list[@]}
			fi
		else

			unset https_proxy
			unset http_proxy
			if [ $email_send == "true" ]; then
				echo "Sending email without proxy"
				python3 script_files/email_send.py $cust_id $prev_month $cur_year $smtp_auth $smtp_server $smtp_server_port $smtp_sender $smtp_password $smtp_subject_prefix ${smtp_list[@]}
			fi
		fi

	else
		# Case for current month January

		if [ $is_proxy_for_email == "true" ]; then
			# if variable is_proxy_for_email is set to true, then proxy will be set for email sending
			if [ $email_send == "true" ]; then
				echo "Sending email using proxy"
				python3 script_files/email_send.py $cust_id $prev_month $prev_year $smtp_auth $smtp_server $smtp_server_port $smtp_sender $smtp_password $smtp_subject_prefix ${smtp_list[@]}
			fi
		else
			unset https_proxy
			unset http_proxy
			if [ $email_send == "true" ]; then
				echo "Sending email without proxy"
				python3 script_files/email_send.py $cust_id $prev_month $prev_year $smtp_auth $smtp_server $smtp_server_port $smtp_sender $smtp_password $smtp_subject_prefix ${smtp_list[@]}
			fi
		fi	
	fi
done

#######################################################################################################
