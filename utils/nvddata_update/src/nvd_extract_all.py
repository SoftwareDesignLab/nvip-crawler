import requests
import json
import mysql.connector


url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
params = {'resultsPerPage': 2000}

all_cves = []
insertedCount = 0

# Connect to the MySQL database
mydb = mysql.connector.connect(
    host="host.docker.internal",
    user="root",
    password="root",
    database="nvip_test"
)

mycursor = mydb.cursor()

while True:
    response = requests.get(url, params=params)
    if response.status_code != 200:
        print(f'Error retrieving CVEs: {response.text}')
        break
    
    cve_data = json.loads(response.text)

    if len(cve_data['vulnerabilities']) == 0:
        break

    all_cves += cve_data['vulnerabilities']
    # Loop through the CVE entries and extract the CVE ID and published date
    for cve in cve_data['vulnerabilities']:

        cve_id = cve["cve"]["id"]
        published_date = cve["cve"]["published"]
        status = cve["cve"]["vulnStatus"]

        # Insert the CVE ID and published date into the database
        sql = "INSERT INTO nvddata (cve_id, published_date, status) VALUES (%s, %s, %s)"
        val = (cve_id, published_date[0:10] + " " + published_date[11:16] + ":00", status)
        
        try:
            mycursor.execute(sql, val)
            # Commit the changes to the database
            mydb.commit()
            print("Inserted:", cve_id, published_date, status)
            insertedCount += 1
        except mysql.connector.IntegrityError as e:
            print(f"Could not insert {cve_id}: {str(e)}")
            mydb.rollback()

        print("CVE ID:", cve_id)
        print("Published Date:", published_date)
        print("Status: ", status)

    print("Adding " + str(len(cve_data['vulnerabilities'])) + " more CVEs from NVD")
    print(str(len(all_cves)) + " Total CVEs")
    print(str(insertedCount) + " CVEs were inserted!")

    # check if there are more pages of results
    total_results = int(cve_data['totalResults'])
    results_per_page = int(cve_data['resultsPerPage'])
    start_index = int(cve_data['startIndex'])
    
    if start_index + results_per_page > total_results:
        break
    
    params['startIndex'] = start_index + results_per_page

print(f'Total CVEs retrieved: {len(all_cves)}')
print("Total inserted " + str(insertedCount))
