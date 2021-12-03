
# National Vulnerability Intelligence Platform (NVIP) - The Backend System
The NVIP back end system is scheduled to run periodically to find CVEs as soon as they are disclosed at CVE Numbering Authority(CNA) web pages. 
It scrapes disclosed CVEs, scores/characterizes them automatically and stores them into the database.

## Main Modules & Features
* NVIP is a full open source software vulnerability management platform developed in Java.
* It crawls provided list of vulnerability sources and creates a dynamic database of Common Vulnerabilities and Exposures (CVE). 
* NVIP provides near real time detection of disclosed vulnerabilities, characterizes them based on the NIST's Vulnerability Description Ontology (VDO). 
* NVIP automatically scores each CVE based on the Common Vulnerability Scoring System Version 3.1 specification.
* It reconciles scraped CVEs using Apache Open NLP. 
* Automatically extracts affected Common Platform Enumeration (CPE) products from free-form CVE descriptions.

### Additional Utilities & Functions
* Maintains an updated list of CVE source URLs, takes a seed URL list as input and searches for additional CVE sources. 
* Compares crawled CVEs against NVD and MITRE and records the comparison results under the "output" directory. 
(If NVIP is run at date "MM/dd/yyyy", the output will be at "output//yyyyMMdd" path.) 

### System Requirements
* NVIP requires Java 8.
* It uses MySQL (version 8) to store CVEs. The database muste be created before running the system. The database dump is provided at '/nvip_data/mysql-database'. 
* Because the crawling process is a multi-threaded process and the characterization and product name extraction trains AI/ML models, minimum 8GB RAM is needed to run the system.
(Suggested JVM parameters: -Xms8g -Xmx16g) 

### Summary of Open Source Technologies/Programs Used
* NVIP uses WEKA (The workbench for machine learning) to train Machine Learning models for CVE characterization: https://www.cs.waikato.ac.nz/ml/weka/
* MySQL database is used to store crawled and characterized CVEs: https://www.mysql.com/
* The Apache Open NLP is used for CVE reconciliation: https://opennlp.apache.org/ 
* The Deeplearning4j framework is used to train Deep Learning (LSTM) models for product name extraction: https://deeplearning4j.org/

### How to Import as Eclipse Maven Project
Eclipse IDE is suggested for development.
NVIP can be imported as an Eclipse Maven project by following the steps listed below:

* Open Eclipse.
* Click File > Import.
* Select "Existing Maven Projects" and Click Next.
* Click Browse and select the root folder of the nvip backend project (which contains the pom.xml file).
* Click Next and then click Finish. 

### How To Run from Eclipse
Follow the steps below to run NVIP from Eclipse:

* Double click on (open) the edu.rit.se.nvip.NVPMain.java, right click and select "Run As > Java Application".
* NVIP will load source URLs from the datasabe and start the crawl process automatically.
* If you want to run NVIP locally for test/development purposes, you need to provide the path of the file that includes source urls from the command line. 
To load source URLs from a file, right click and then go to Run As->Run Configurations->Arguments and enter the file path, stg. like 'src/test/resources/cve-source-2URLs.txt'
* To configure nvip for MySQL database, please follow instrustions at the "Download and Integrate MySQL" section below.

### Important Notes - Troubleshooing
- There are two config files used. 'nvip.properties' is used to set program parameters, and 'db-mysql.properties' is used to set database parameters. 
When the system is run, the config files are first searched in the application root, if they are not found there the ones at '\src\main\resources' are used!

- Please make sure the user name and password parameters in the 'db-mysql.properties' are set correctly! The user (root) and password parameters should be the ones set while installing MySQL.   

- Required training data and resources are stored under the nvip_data (the data directory). You need to configure the NVIP data directory of the project (in the nvip.properties) to point to the nvip_data directory. 
The data directory of the NVIP project can be set by the "dataDir" in the nvip.properties file at src/main/resources/nvip.properties.

> Ex: assuming you have the data directory at C:/nvip/nvip_data, and the NVIP backend project at C:/nvip/nvip_backend, then you need to set dataDir = ../nvip_data in the nvip.properties.

### How to Build & Package
Follow the steps below to generate NVIP output jars:

* After the project is imported, right click on the pom.xml and click "Run As > Maven Build" to generate output jars. 
* Set "package" as Maven goal.
* After the build process, the output jar will be located under the "target" directory of the project root.

### Download and Integrate MySQL
* Download “mysql-installer-community-8.0.20.0.msi” from  https://dev.mysql.com/downloads/installer/.
* Click on the downloaded file, choose “Full” installation and continue with default options.
* During the configuration of MySQL Server, when prompted for a password (for user "root"), make sure you use the "same password" that you have at "\src\main\resources\db-mysql.properties". 
* After the setup process is finished open "MySQL Workbench" program (Click start and search for "MySQL Workbench" to find it).
* Click on "Database/Connect To Database" menu on MySQL Workbench and Click "Ok". Enter the password you set for user "root" earlier. You should be connected to the MySQL database.
* Open a new query editor in MySQL Workbench and execute the script provided at '\nvip_data\mysql-database\' to create and initialize the MySQL database.
> Please make sure the MySQL user name and password parameters are set properly in the 'db-mysql.properties'! 