import openai
import json
import pika
from limiter import Limiter
import threading
import concurrent.futures
from queue import PriorityQueue
import logging
import time
import tiktoken


# DOCKER SET UP
# docker build -t openaiapp .
# docker run openaiapp

class Request:
    def __init__(self, api_key, sys_msg, usr_msg, temp, job_id, requestor, priority):
        self.api_key = api_key
        self.sys_msg = sys_msg
        self.usr_msg = usr_msg
        self.temp = temp
        self.jobid = job_id + 1
        self.messages = [sys_msg, usr_msg]
        self.requestor = requestor
        self.priority = priority

    def __lt__(self, other):
        if self.requestor == other.requestor:
            return self.priority < other.priority
        return self.requestor.__lt__(other.requestor)

class Message:
    def __init__(self, role, content):
        self.role = role
        self.content = content

class openAiMessageHandler:

    MSG_BUCKET: str = 'messages'
    limit_msgs: Limiter = Limiter(bucket=MSG_BUCKET)
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.requestQueue = PriorityQueue(maxsize=1000)
        self.mainExecutor = concurrent.futures.ThreadPoolExecutor()
        self.requestExecutor = concurrent.futures.ThreadPoolExecutor()
        self.request_queue = PriorityQueue()
        self.init_executors()

    def init_executors(self):
        self.mainExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.mainExecutor.submit(self.handle_requests)
        self.requestExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=5)

    def handle_requests(self):
        while True:
            time.sleep(.3)
            try:
                request = self.request_queue.get()
            except KeyboardInterrupt:
                return
            except Exception as e:
                self.logger.error("Exception while getting request from queue:", exc_info=True)
                return
            tokens = self.get_token_count(request)
            self.wait_for_limiters()
            self.requestExecutor.submit(lambda: self.send_request(request))

    def send_request(self, request):
        # RabbitMQ configuration for the output queue
        rabbitmq_host = 'localhost'  # host.docker.internal
        output_queue = 'openai_responses'

        connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host))
        channel = connection.channel()
        channel.queue_declare(queue=output_queue)
        print(request.usr_msg)
        response = self.get_openai_response(request.api_key, request.sys_msg.content, request.usr_msg.content, request.temp)
        json_response = {
            "job_id": request.jobid,
            "message": response
        }

        response_bytes = json.dumps(json_response).encode()

        channel.basic_publish(exchange='', routing_key=output_queue, body=response_bytes)
        print("sent response")

        connection.close()

    def wait_for_limiters(self):
        self.token_limiter.try_acquire("gptlimit")

    def get_token_count(self, request):
        encoding = tiktoken.encoding_for_model("gpt-3.5-turbo")
        tokens_per_msg = 4
        token_count = 0
        for msg in request.messages:
            token_count += tokens_per_msg
            token_count += len(encoding.encode(msg.role))
            token_count += len(encoding.encode(msg.content))
        return token_count

    def get_openai_response(self, api_key, system_message, user_message, temperature):
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

    def rabbitmq_callback(self, channel, method, properties, body):  # just put in queue
        try:
            print("Retrieved message from Rabbit")
            # Parse the incoming RabbitMQ message as JSON
            body = body.decode()
            message_data = json.loads(body)

            # Extract the relevant fields
            api_key = message_data.get("openai_api_key", "")
            sys_msg = message_data.get("system_message", "")
            usr_msg = message_data.get("user_message", "")
            temp = message_data.get("temperature", 0.0)
            requestor_prio_id = message_data.get("requestorPrioId", 2)
            prio_id = message_data.get("PrioId")
            job_id = message_data.get("JobID")

            user = Message("user", usr_msg)
            sys = Message("system", sys_msg)
            self.request_queue.put(Request(api_key, sys, user, temp, job_id, requestor_prio_id, prio_id))

        except json.JSONDecodeError:
            print("Invalid JSON format received from RabbitMQ.")
        except Exception as e:
            print(f"An error occurred: {e}")

    def main(self):
        # RabbitMQ's configuration for the input queue
        rabbitmq_host = 'localhost'  # host.docker.internal
        rabbitmq_queue = 'openai_requests'

        connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host))
        channel = connection.channel()
        channel.queue_declare(queue=rabbitmq_queue)
        channel.basic_consume(queue=rabbitmq_queue, on_message_callback=self.rabbitmq_callback, auto_ack=True)

        print(f"[*] Waiting for rabbit messages. To exit, press CTRL+C")

        try:
            channel.start_consuming()
        except KeyboardInterrupt:
            print("Exiting...")
            connection.close()


if __name__ == "__main__":
    message_handler = openAiMessageHandler()
    message_handler.main()
