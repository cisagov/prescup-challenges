# It's Got to be Somebody's Data

_Setup_

1. Create an Ubuntu Linux machine and run the following commands to install required packages:
```bash
sudo apt update
sudo apt install python3 tensorflow-cpu opencv-python pytesseract sklearn torch tesseract-ocr libtesseract-dev detecto scipy matplotlib wave ffmpeg
```

2. Follow these links to install [PostgreSQL](https://www.postgresql.org/download/linux/ubuntu/) and [MongoDB](https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu/) on your existing Ubuntu Linux machine or a separate machine.  

3. Use the [mongo-eventsdb-event_data.json](mongo-eventsdb-event_data.json) script to create the Mongo database.

4. Use the [postgres_db.sql](postgres_db.sql) script to create the PostgreSQL database.   

5. Reference the [Star_Name_ID.csv](Star_Name_ID.csv) file to correlate the data stored in the databases.   

6. [This separate download](https://presidentscup.cisa.gov/files/pc4/teams-round3-its-got-to-be-somebodys-data.zip) contains the files needed to solve each of the four questions with the following folders: QUESTION1, QUESTION2, QUESTION3, QUESTION4. 
