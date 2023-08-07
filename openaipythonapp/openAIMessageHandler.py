import openai
import json
import asyncio
import aio_pika
from pyrate_limiter import Duration, RequestRate, Limiter
import threading
import concurrent.futures
from queue import PriorityQueue
import logging


# DOCKER SET UP
# docker build -t openaiapp .
# docker run openaiapp
def __init__(self):
    self.logger = logging.getLogger(self.__class__.__name__)
    self.requestQueue = PriorityQueue(maxsize=1000)
    self.token_rate_limit = 90000
    self.request_rate_limit = 3500
    self.token_request_rate = RequestRate(self.token_rate_limit, 60)  # Tokens per minute
    self.request_request_rate = RequestRate(self.request_rate_limit, 60)  # Requests per minute
    self.token_limiter = Limiter(self.token_request_rate)
    self.request_limiter = Limiter(self.request_request_rate)
    self.mainExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    self.requestExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=5)
    self.init_executors()


class Request:
    def __init__(self, api_key, sys_msg, usr_msg, temp, job_id, requestor, priority):
        self.api_key = api_key
        self.sys_msg = sys_msg
        self.usr_msg = usr_msg
        self.temp = temp
        self.jobid = job_id
        self.messages = [usr_msg, sys_msg]
        self.requestor = requestor
        self.priority = priority


    def __lt__(self, other):
        if self.requestor == other.requestor:
            return self.priority - other.priority
        return self.requestor.__lt__(other.requestor)



def init_executors(self):
    self.mainExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    self.handlerThreadFuture = self.mainExecutor.submit(handle_requests)
    self.requestExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=5)


async def handle_requests(self):
    while True:
        try:
            request = request_queue.get()
        except KeyboardInterrupt:
            return
        except Exception as e:
            self.logger.error("Exception while getting request from queue:", exc_info=True)
            return
        tokens = chat_completion_token_count(self, request)
        self.wait_for_limiters(tokens)
        self.requestExecutor.submit(lambda: send_request(request))


async def send_request(request):
    # RabbitMQ configuration for the output queue
    rabbitmq_host = 'localhost'  # host.docker.internal
    output_queue = 'openai_responses'

    # Connect to RabbitMQ for publishing the response
    connection = await aio_pika.connect_robust(host=rabbitmq_host)
    channel = await connection.channel()

    # Declare the output queue
    await channel.declare_queue(output_queue)

    response = await get_openai_response_async(request.api_key, request.sys_msg, request.usr_msg, request.temp)
    json_response = {
        "job_id": request.jobid,
        "message": response
    }

    response_bytes = json.dumps(json_response).encode()

    # Publish the OpenAI API response to the output queue
    await channel.default_exchange.publish(aio_pika.Message(body=response_bytes), routing_key=output_queue)
    print("sent response")
    # Close the connection after sending all responses
    await connection.close()


def wait_for_limiter(self):
    self.token_limiter.try_acquire("gptlimit")


def chat_completion_token_count(self, request):
    return self.chat_completion_token_count_with_encoding(request.messages)


def chat_completion_token_count_with_encoding(self, messages):
    tokens_per_msg = 4
    token_count = 0
    for msg in messages:
        token_count += tokens_per_msg
        token_count += len(self.tokenizer.tokenize(msg.content))
        token_count += len(self.tokenizer.tokenize(msg.role))
    return token_count


def get_openai_response(api_key, system_message, user_message, temperature):
    openai.api_key = api_key

    data = {
        "messages": [
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_message}
        ],
        "temperature": temperature,
        "max_tokens": 1000,
        "model": "gpt-3.5-turbo"
    }

    try:
        response = openai.ChatCompletion.create(**data)
        return response['choices'][0]['message']['content']
    except openai.error.OpenAIError as err:
        print(f"An error occurred: {err}")


request_queue = PriorityQueue()


async def rabbitmq_callback(message: aio_pika.IncomingMessage):  # just put in queue
    try:
        async with message.process():
            print("Retrieved message from Rabbit")
            # Parse the incoming RabbitMQ message as JSON
            body = message.body.decode()
            message_data = json.loads(body)

            # Extract the relevant fields
            api_key = message_data.get("openai_api_key", "")
            sys_msg = message_data.get("system_message", "")
            usr_msg = message_data.get("user_message", "")
            temp = message_data.get("temperature", 0.0)
            requestor_prio_id = message_data.get("requestorPrioId", 2)
            prio_id = message_data.get("PrioId")
            job_id = message_data.get("JobID")

            request_queue.put(Request(api_key, sys_msg, usr_msg, temp, job_id, requestor_prio_id, prio_id))



    except json.JSONDecodeError:
        print("Invalid JSON format received from RabbitMQ.")
    except Exception as e:
        print(f"An error occurred: {e}")


async def get_openai_response_async(api_key, system_message, user_message, temperature):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, get_openai_response, api_key, system_message, user_message, temperature)


async def main():
    # RabbitMQ's configuration for the input queue
    rabbitmq_host = 'localhost'  # host.docker.internal
    rabbitmq_queue = 'openai_requests'

    # Connect to RabbitMQ
    connection = await aio_pika.connect_robust(host=rabbitmq_host)
    channel = await connection.channel()

    # Declare the input queue
    queue = await channel.declare_queue(rabbitmq_queue)

    # Set up a consumer to listen for messages from RabbitMQ
    await queue.consume(rabbitmq_callback)

    # new thread pointed towards new method to call openai (read from queue, send request) within make more threads
    # to send request and handle response

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
