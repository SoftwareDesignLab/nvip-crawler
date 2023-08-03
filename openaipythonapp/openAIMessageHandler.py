import openai
import json
import asyncio
import aio_pika
from queue import PriorityQueue


# DOCKER SET UP
# docker build -t openaiapp .
# docker run openaiapp

class Request:
    def __init__(self, sys_msg, usr_msg, temp):
        self.sys_msg = sys_msg
        self.usr_msg = usr_msg
        self.temp = temp


class NestedPriorityQueue:
    def __init__(self, queue):
        self.queue = queue


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


priorityRequestor_queue = PriorityQueue()
priorityId_queue = PriorityQueue()
response_dict = {}  # Dictionary to store responses for each request


async def rabbitmq_callback(message: aio_pika.IncomingMessage):
    try:
        async with message.process():
            print("Retrieved message from Rabbit")
            # Parse the incoming RabbitMQ message as JSON
            body = message.body.decode()
            message_data = json.loads(body)

            # Extract the relevant fields
            openai_api_key = message_data.get("openai_api_key", "")
            sys_msg = message_data.get("system_message", "")
            usr_msg = message_data.get("user_message", "")
            temp = message_data.get("temperature", 0.0)
            requestor_prio_id = message_data.get("requestorPrioId", 2)
            prio_id = message_data.get("PrioId")

            # RabbitMQ configuration for the output queue
            rabbitmq_host = 'host.docker.internal'
            output_queue = 'openai_responses'

            # Connect to RabbitMQ for publishing the response
            connection = await aio_pika.connect_robust(host=rabbitmq_host)
            channel = await connection.channel()

            # Declare the output queue
            await channel.declare_queue(output_queue)

            # Push the message into the priority queue
            # The priority queue will sort the messages based on priority and requestor priority
            priorityId_queue.put((prio_id, Request(sys_msg, usr_msg, temp)))
            priorityRequestor_queue.put((requestor_prio_id, NestedPriorityQueue(priorityId_queue)))

            while not priorityRequestor_queue.empty():
                # Pop the message with the highest priority from the queue
                requestorQueue = priorityRequestor_queue.get()
                while not requestorQueue[1].queue.empty():
                    request = requestorQueue[1].queue.get()
                    system_message = request[1].sys_msg
                    user_message = request[1].usr_msg
                    temperature = request[1].temp

                    response = await get_openai_response_async(openai_api_key, system_message, user_message,
                                                               temperature)

                    # Store the response in the dictionary with user_message as the key
                    response_dict[user_message] = response

                    # Publish the OpenAI API response to the output queue
            # Get the OpenAI response asynchronously
            # Get the OpenAI response asynchronously
            response = await get_openai_response_async(openai_api_key, system_message, user_message, temperature)

            # Encode the response string before publishing it to the output queue
            response_bytes = response.encode()

            # Publish the OpenAI API response to the output queue
            await channel.default_exchange.publish(aio_pika.Message(body=response_bytes), routing_key=output_queue)
            print("sent response")
            # Close the connection after sending all responses
            await connection.close()

    except json.JSONDecodeError:
        print("Invalid JSON format received from RabbitMQ.")
    except Exception as e:
        print(f"An error occurred: {e}")


async def get_openai_response_async(api_key, system_message, user_message, temperature):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, get_openai_response, api_key, system_message, user_message, temperature)


async def main():
    # RabbitMQ's configuration for the input queue
    rabbitmq_host = 'host.docker.internal'
    rabbitmq_queue = 'openai_requests'

    # Connect to RabbitMQ
    connection = await aio_pika.connect_robust(host=rabbitmq_host)
    channel = await connection.channel()

    # Declare the input queue
    queue = await channel.declare_queue(rabbitmq_queue)

    # Set up a consumer to listen for messages from RabbitMQ
    await queue.consume(rabbitmq_callback)

    print(f"[*] Waiting for rabbit messages. To exit, press CTRL+C")
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("Exiting...")
        # Gracefully close the connection when Ctrl+C is pressed
        await connection.close()


if __name__ == "__main__":
    asyncio.run(main())
