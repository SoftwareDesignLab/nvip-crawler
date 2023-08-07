# Use the official Python image as the base image
FROM python:3.9

# Set the working directory inside the container
WORKDIR /app

# Disable output buffering in Python
ENV PYTHONUNBUFFERED 1

# Copy the 'openAIMessageHandler.py' script to the container's working directory
COPY openAIMessageHandler.py /app/

# Install the 'pika' library to interact with RabbitMQ
RUN pip install aio_pika
RUN pip install openai
RUN pip install pyrate-limiter

# Run the Python script when the container starts
CMD ["python", "openAIMessageHandler.py"]