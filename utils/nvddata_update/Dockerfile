# Use an official Python runtime as the base image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the Python script to the working directory
COPY /src/nvd_extract_all.py /app

RUN pip install requests
RUN pip install mysql-connector-python


# Set the command to run when the container starts
CMD ["python", "nvd_extract_all.py"]
