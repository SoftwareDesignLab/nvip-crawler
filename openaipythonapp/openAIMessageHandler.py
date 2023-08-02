import pika
import openai
import json
import heapq

#DOCKER SET UP
#docker build -t openaiapp .
#docker run openaiapp

class RequestWrapper:
    def __init__(self, requestor, priority, message_data):
        self.requestor = requestor
        self.priority = priority
        self.message_data = message_data

    def __lt__(self, other):
        if self.requestor == other.requestor:
            return self.priority < other.priority
        return self.requestor < other.requestor


def get_openai_response(api_key, system_message, user_message, temperature):
    openai.api_key = api_key

    data = {
        "messages": [
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_message}
        ],
        "temperature": temperature,
        "max_tokens": 1000,  # Adjust the max_tokens parameter as needed
        "model": "gpt-3.5-turbo"
    }

    try:
        response = openai.ChatCompletion.create(**data)
        return response['choices'][0]['message']['content']
    except openai.error.OpenAIError as err:
        print(f"An error occurred: {err}")


def rabbitmq_callback(ch, method, properties, body):
    try:
        print("Retrieved message from Rabbit")
        # Parse the incoming RabbitMQ message as JSON
        message_data = json.loads(body)

        # Extract the relevant fields
        openai_api_key = message_data.get("openai_api_key", "")
        system_message = message_data.get("system_message", "")
        user_message = message_data.get("user_message", "")
        temperature = message_data.get("temperature", 0.0)
        requestor_prio_id = message_data.get("requestorPrioId", 2)
        prio_id = message_data.get("PrioId")

        # Calculate the priority for the message using the 'PrioId' field
        # The lower the value, the higher the priority
        priority = prio_id

        # Create a RequestWrapper object to represent the message and its priority
        request_wrapper = RequestWrapper(requestor_prio_id, priority, message_data)

        # RabbitMQ configuration for the output queue
        rabbitmq_host = 'host.docker.internal'
        output_queue = 'openai_responses'

        # Connect to RabbitMQ for publishing the response
        connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host))
        channel = connection.channel()

        # Declare the output queue
        channel.queue_declare(queue=output_queue)

        # Push the message into the priority queue
        # The priority queue will sort the messages based on priority and requestor priority
        priority_queue = []
        heapq.heappush(priority_queue, request_wrapper)

        while priority_queue:
            # Pop the message with the highest priority from the queue
            request_wrapper = heapq.heappop(priority_queue)
            message_data = request_wrapper.message_data
            openai_api_key = message_data.get("openai_api_key", "")
            system_message = message_data.get("system_message", "")
            user_message = message_data.get("user_message", "")
            temperature = message_data.get("temperature", 0.0)

            response = get_openai_response(openai_api_key, system_message, user_message, temperature)

            # Publish the OpenAI API response to the output queue
            channel.basic_publish(exchange='',
                                  routing_key=output_queue,
                                  body=response)

            print("sent response")

        # Close the connection after sending all responses
        connection.close()

    except json.JSONDecodeError:
        print("Invalid JSON format received from RabbitMQ.")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    # RabbitMQ's configuration for the input queue
    rabbitmq_host = 'host.docker.internal'
    rabbitmq_queue = 'openai_requests'

    # Connect to RabbitMQ
    connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host))
    channel = connection.channel()

    # Declare the input queue
    channel.queue_declare(queue=rabbitmq_queue)

    # Set up a consumer to listen for messages from RabbitMQ
    channel.basic_consume(queue=rabbitmq_queue, on_message_callback=rabbitmq_callback, auto_ack=True)

    print(f"[*] Waiting for rabbit messages. To exit, press CTRL+C")
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        print("Exiting...")
        # Gracefully close the connection when Ctrl+C is pressed
        channel.stop_consuming()
        connection.close()
