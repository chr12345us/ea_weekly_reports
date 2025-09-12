import sys
import sqlite3

cust_id = sys.argv[1]
currentmonth = int(sys.argv[2])
currentyear = int(sys.argv[3])
prevyear = int(currentyear -1)

path_r = f'./report_files/'
path_d = f'./database_files/{cust_id}/'

con = sqlite3.connect(path_d + 'database_'+cust_id+'.sqlite')

if currentmonth == 1:
	con.execute(f"delete from attacks where month<8 and year={prevyear}")
if currentmonth == 2:
	con.execute(f"delete from attacks where month<9 and year={prevyear}")
if currentmonth == 3:
	con.execute(f"delete from attacks where month<10 and year={prevyear}")
if currentmonth == 4:
	con.execute(f"delete from attacks where month<11 and year={prevyear}")
if currentmonth == 5:
	con.execute(f"delete from attacks where month<12 and year={prevyear}")
if currentmonth == 6:
	con.execute(f"delete from attacks where year={prevyear}")
if currentmonth > 6:
	con.execute(f"delete from attacks where month<={currentmonth-6} and year={currentyear}")
		

con.commit()

con.execute("VACUUM")

con.commit()

con.close()
