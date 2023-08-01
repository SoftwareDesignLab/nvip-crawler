import pika
import openai
import json

#DOCKER SET UP
#docker build -t openaiapp .
#docker run openaiapp
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

        response = get_openai_response(openai_api_key, system_message, user_message, temperature)

        # RabbitMQ configuration for the output queue
        rabbitmq_host = 'host.docker.internal'
        output_queue = 'openai_responses'

        # Connect to RabbitMQ for publishing the response
        connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host))
        channel = connection.channel()

        # Declare the output queue
        channel.queue_declare(queue=output_queue)

        # Publish the OpenAI API response to the output queue
        channel.basic_publish(exchange='',
                              routing_key=output_queue,
                              body=response)

        print("sent response")
        # Close the connection after sending the response
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
