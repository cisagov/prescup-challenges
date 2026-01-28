FROM TBD.dkr.ecr.us-east-1.amazonaws.com/pc7/challenge-server

# Install anything you need like installing ssh and adding keys, installing python packages, etc.
RUN pip install pyyaml requests
RUN pip install paramiko reportlab

# Copy the config over
COPY ./grader_config.yml /config.yml

# Optional; if none needed, leave empty.py (no-op) as the startup script in the config and disable grading 
#   You can only define one grading script; if you need multiple, you'll need to write a single master script to handle the subscripts
#   Also, make sure the all have their proper shebangs!

COPY ./grading.py ./gradeInternalFixed.py ./gradeInternalRemoval.py ./gradePublicFixed.py ./gradePublicRemoval.py /custom_scripts/

# Don't forget to make them executable!
RUN chmod -R +x /custom_scripts

