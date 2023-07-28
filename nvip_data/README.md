
# NVIP Data Repository

This repo contains the data/resources needed to run the NVIP project.

### Quick info about each REQUIRED sub-directory 
* ./mysql-database: The dump of the MySQL database. 
> You need to install MySQL and create the nvip database before running the nvip system. After you install MySQL you should tune the parameters (i.e. user and password) in the db-mysql.properties file! 
* ./characterization: Training data (CSV files) for AI/ML-based CVE characterization.
* ./productnameextraction: Training data and resources used to extract product names from CVE descriptions via LSTM.
  * CPEmap.ser: serialized Java HashMap containing list of CPEs to be loaded in nvip_backend/productnameextractor
  * NER Model bins: (Named Entity Recognition Model) used for classifying words in a given CVE description
    * Source: https://www.usenix.org/system/files/sec19-dong.pdf
    * Usage: nvip_backend/.../productnameextractor/aimodels.NERModel.java
  * C2V/W2V Model bins: aimodels.Char2Vector/Word2vec language models used with NER to process words as 1D vector of features
    * Source: https://hackernoon.com/chars2vec-character-based-language-model-for-handling-real-world-texts-with-spelling-errors-and-a3e4053a147d
    * Usage: nvip_backend/.../productnameextractor/aimodels.Char2Vector.java, Word2vec.java
* ./cvss: Data/script used for CVSS scoring. 
* en-sent.bin: Apache Open NLP english sentence detector model file
  * Source: http://opennlp.sourceforge.net/models-1.5/
  * Usage: nvip_ui/.../TwitterApi, nvip_backend/.../productnameextractor/aimodels.NERModel
* edbid.bin: Exploit DB ID to CVE-ID saved map, saved/loaded to prevent need for visiting db urls each time class is loaded
  * Source/Usage: nvip_backend/.../exploit/ExploitScraper.java

### How to Use
You should clone this directory (nvip_data) and add its path as NVIP data path in the 'nvip.properties' file of the nvip_backend project.
> Ex: dataDir = ../nvip_data

### Command for Liquibase
Once you have a database created, run this command in the mysql-database/newDB
directory

> liquibase --changeLogFile=db.init.xml --classpath=./mysql-connector-j-8.0.33.jar --url="jdbc:mysql://localhost:3306/DB_Name" 
> --username=USERNAME --password=PASSWORD update

- USERNAME --> MySQL Username
- PASSWORD --> MySQL Password
- DB Name --> MySQL DB Name