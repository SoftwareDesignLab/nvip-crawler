
# NVIP - The Backend System
The NVIP back end system is scheduled to run periodically to find CVEs as soon as they are disclosed at CVE Numbering Authority(CNA) web pages. 
It scrapes disclosed CVEs, scores/characterizes them automatically and stores them into the database.

* NVIP is a full open source software vulnerability management platform developed in Java.
* It crawls provided list of vulnerability sources and creates a dynamic database of Common Vulnerabilities and Exposures (CVE). 
* NVIP provides near real time detection of disclosed vulnerabilities, characterizes them based on the NIST's Vulnerability Description Ontology (VDO). 
* NVIP automatically scores each CVE based on the Common Vulnerability Scoring System Version 3.1 specification.
* It reconciles scraped CVEs using Apache Open NLP. 
* Automatically extracts affected Common Platform Enumeration (CPE) products from free-form CVE descriptions.
* Maintains an updated list of CVE source URLs, takes a seed URL list as input and searches for additional CVE sources. 
* Compares crawled CVEs against NVD and MITRE and records the comparison results under the "output" directory. 
(If NVIP is run at date "MM/dd/yyyy", the output will be at "output//yyyyMMdd" path.)
* NVIP consists of multiple modules which send jobs to each other via RabbitMQ, and share the `db` module as a common dependency.

## System Requirements
* NVIP requires at least Java version 8.
  - Download Link: https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html


* NVIP uses MySQL (version 8) to store CVEs. The database muste be created before running the system. The current database dump is provided at '/nvip_data/mysql-database'. 
  - Download Link: https://dev.mysql.com/downloads/installer/


* We're also going to be using Liquibase for updating and tracking changes to the database schema.
  - Download Link: https://www.liquibase.com/download



* Java Maven is used to compile the project with its requirements.
  - Download Link: https://maven.apache.org/download.cgi


* We also use Docker for building and deploying the project.
  - Download Link: https://docs.docker.com/engine/install/


* Because the crawling process is a multi-threaded process and the characterization and product name extraction trains AI/ML models, minimum 8GB RAM is needed to run the system.

## Summary of Open Source Technologies/Systems Used
* NVIP uses Crawler4j to conduct multi-threaded web crawling for CVE data: https://github.com/rzo1/crawler4j


* NVIP uses WEKA (The workbench for machine learning) to train Machine Learning models for CVE characterization: https://www.cs.waikato.ac.nz/ml/weka/



* MySQL database is used to store crawled and characterized CVEs: https://www.mysql.com/



* The Apache Open NLP is used for CVE reconciliation: https://opennlp.apache.org/ 



* The DeepLearning4j framework is used to train Deep Learning (LSTM) models for product name extraction: https://deeplearning4j.org/


* NVIP also uses Log4j for logging errors and state: https://logging.apache.org/log4j/2.x/javadoc.html


# Installation and Setup Guide (w/ Docker)

## 1. Download & Install MySQL, Create the Database
* Download “mysql-installer-community-8.0.20.0.msi” from  https://dev.mysql.com/downloads/installer/.


* Click on the downloaded file, choose “Full” installation and continue with default options.


* During the configuration of MySQL Server, when prompted for a password (for user "root"), make sure you use the "same password" that you have at the **HIKARI_PASSWORD** Environment Variable.

## 2. Create Database (via MySQL Workbench)
* After the setup process is finished open "MySQL Workbench" program (Click start and search for "MySQL Workbench" to find it).


* Click on "Database/Connect To Database" menu on MySQL Workbench and Click "Ok". Enter the password you set for user "root" earlier. You should be connected to the MySQL database.


* Once you have a database created, run this command in the mysql-database/newDB directory:

> liquibase --changeLogFile=db.init.xml --classpath=./mysql-connector-j-8.0.33.jar --url="jdbc:mysql://localhost:3306/DB Name" --username=USERNAME --password=PASSWORD update


## 3. Build & Package
Make sure you can build the project before setting it up with docker
From the root directory, run the following command via cmd line to install dependencies:

    $ mvn clean install

If successful, run the following command to package the Maven project into a jar file

    $ mvn package -DskipTests`

You can also run unit tests separately with the Maven test command:

    $ mvn test

After the build process, the output jar will be located under the "target" directory of the project root.
This is the Jar file that Docker will use to run the application.
If you're using Docker (which is the prefferred way of running it), you don't have to worry about the jar file as long as it builds.


## 4. Install Docker and Build via Docker CLI


### Running the Crawler

`docker run -d --rm --memory=10g --env-file=./nvip.env --volume=./crawler-output:/usr/local/lib/output --volume=exploit-repo:/usr/local/lib/nvip_data/exploit-repo --volume=mitre-cve:/usr/local/lib/nvip_data/mitre-cve --name=nvip-crawler ghcr.io/softwaredesignlab/nvip-crawler:latest` 

### Running the Reconciler

`docker run -d --env-file=./nvip.env --name=nvip-reconciler ghcr.io/softwaredesignlab/nvip-reconciler:latest`

### Running the Product Name Extractor

`docker run -d --env-file=./nvip.env --name=nvip-productnameextractor ghcr.io/softwaredesignlab/nvip-productnameextractor:latest`

### Running the Patchfinder

`docker run -d --env-file=./nvip.env --name=nvip-patchfinder ghcr.io/softwaredesignlab/nvip-patchfinder:latest`

# Component Documentation


### Overview
This project consists of 6 main components.

*  **CVE Web Crawler**
   - Uses Multi Threaded Web Crawling for navigating source pages to grab raw CVE data
   

*  **CVE Reconciler** 
   - Reconciles information found for CVEs, each CVE will likely have data from multiple sources.
   To merge that data, the reconciler uses an automated Natural Language Process model for finding the best 
   description for each CVE.


*  **CVE Characterizer** (included in the reconciler module)
   - This component provides automated CVSS scores and VDO Labels for each CVE via a Natural Language Processing model, which is trained
   via the data provided in `nvip_data` (Model is also here as well). It also uses an SSVC API running in the NVIP environment for SSVC scoring.
   - NIST's CVSS score summary: https://nvd.nist.gov/vuln-metrics/cvss
   - NIST's VDO Label summary: https://csrc.nist.gov/csrc/media/publications/nistir/8138/draft/documents/nistir_8138_draft.pdf 


*  **NVD/MITRE Comparisons** (included in the reconciler module)
   - This component processes the compiled CVEs by storing them in the Database, then compares each CVE in NVIP to the 
   CVEs in NVD and MITRE to compare performance of NVIP vs NVD and MITRE.
   - NVD: https://nvd.nist.gov/
   - MITRE:  https://www.cve.org/
   - For comparing with NVD, we're currently transitioning to NVD's 2.0 API: https://nvd.nist.gov/developers/vulnerabilities 


*  **Product Name Extractor**
   - This component identifies affected products in a CVE via a Named Entity Recognition (NER) model.
   - The model and its training data is provided in `nvip_data`
   - Each extracted product is converted as a Common Product Enumeration (CPE) string 
   - CPE Definition and Dictionary(s): https://nvd.nist.gov/products/cpe
   - 

*  **CVE Patch/Fix Finder**
   - This component identifies possible patches for CVEs
   - Patches are found by crawling available repos for the affected products of a CVE
   - Each repo is cloned, then each commit is navigated to identify patches by checking for keywords in the commit messages
   - Product repos are cloned in `nvip_data`, then deleted afterwards after being used
   - **NOTE** This component relies directly on the affected product data from product extraction
   - Fixes are found with web-scrapers similarly to the CVE crawler

# Project Team
- Mehdi Mirakhorli, Principal Investigator
- Ahmet Okutan, Senior Research Developer
- Chris Enoch, Senior Project Manager
- Peter Mell, Collaborator
- Igor Khokhlov, Researcher
- Joanna Cecilia Da Silva Santos, Researcher
- Danielle Gonzalez, Researcher
- Celeste Gambardella, Researcher
- Olivia Gallucci, Vulnerability Researcher
- Steven Simmons, Developer
- Ryan Bryla, Developer
- Andrew Pickard, Developer
- Brandon Cooper, Developer
- Braden Little, Developer
- Adam Pang, Developer
- Anthony Ioppolo, Developer
- Andromeda Sawtelle, Developer
- Corey Urbanke, Developer
- James McGrath, Developer
- Matt Moon, Developer
- Stephen Shadders, Developer
- Paul Vickers, Developer
- Richard Sawh, Developer
- Greg Lynskey, Developer
- Eli MacDonald, Developer
- Ryan Moore, Developer
- Mackenzie Wade, Developer

