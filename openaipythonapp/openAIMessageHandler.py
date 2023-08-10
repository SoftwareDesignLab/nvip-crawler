import openai
import json
import pika
import concurrent.futures
from queue import PriorityQueue
import logging
import time
import tiktoken


# DOCKER SET UP
# docker build -t openaiapp .
# docker run openaiapp


# DEVELOPMENT STOPPED 8/10/23 DUE TO HESITATION TO USE CHATGPT/OPENAI
class Request:  # request class that takes in and builds requests to sent to chatgpt
    def __init__(self, api_key, sys_msg, usr_msg, temp, job_id, requestor, priority, max_tokens):
        self.api_key = api_key
        self.sys_msg = sys_msg
        self.usr_msg = usr_msg
        self.temp = temp
        self.jobid = job_id + 1
        self.messages = [sys_msg, usr_msg]
        self.requestor = requestor
        self.priority = priority
        self.attempts_left = 1
        self.max_tokens = max_tokens

    def __lt__(self, other):
        if self.requestor == other.requestor:
            return self.priority < other.priority
        return self.requestor.__lt__(other.requestor)


class Message: # simple message class that defines a role (system, user, assistant) and the content (the message itself)
    def __init__(self, role, content):
        self.role = role
        self.content = content


class openAiMessageHandler:
    rate_limit_time_interval = 10
    max_requests_per_minute = 3500
    max_tokens_per_minute = 50000

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.requestQueue = PriorityQueue(maxsize=1000)
        self.retry_queue = PriorityQueue(maxsize=1000)
        self.mainExecutor = concurrent.futures.ThreadPoolExecutor()
        self.requestExecutor = concurrent.futures.ThreadPoolExecutor()
        self.request_queue = PriorityQueue()
        self.last_update_time = time.time()
        self.available_request_capacity = 0  # openAiMessageHandler.max_requests_per_minute * openAiMessageHandler.rate_limit_time_interval / 60
        self.available_token_capacity = 0  # openAiMessageHandler.max_tokens_per_minute * openAiMessageHandler.rate_limit_time_interval / 60
        self.init_executors()
        self.count = 0

    def init_executors(self):
        self.mainExecutor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.mainExecutor.submit(self.handle_requests)
        self.requestExecutor = concurrent.futures.ThreadPoolExecutor()

    def handle_requests(self): #separate thread to always listen for new requests from the queue
        while True:
            time.sleep(.3)
            try:
                if self.retry_queue.qsize() == 0:
                    request = self.request_queue.get()
                else:
                    print("Retrying request")
                    time.sleep(5)
                    request = self.retry_queue.get()
            except KeyboardInterrupt:
                return
            except Exception as e:
                self.logger.error("Exception while getting request from queue:", exc_info=True)
                return
            self.wait_for_limiters(request)
            self.requestExecutor.submit(lambda: self.send_request(request))

    def send_request(self, request):
        # RabbitMQ configuration for the output queue
        rabbitmq_host = 'localhost'  # host.docker.internal
        output_queue = 'openai_responses'

        connection = pika.BlockingConnection(pika.ConnectionParameters(host=rabbitmq_host))
        channel = connection.channel()
        channel.queue_declare(queue=output_queue)
        response = self.get_openai_response(request)
        json_response = {
            "job_id": request.jobid,
            "message": response
        }

        response_bytes = json.dumps(json_response).encode()

        channel.basic_publish(exchange='', routing_key=output_queue, body=response_bytes)
        self.count += 1
        print(f"sent response: {self.count}")

        connection.close()

    def wait_for_limiters(self, request): #waits for tokens to be available to send to chatgpt
        tokens = self.get_token_count(request)
        while True:
            time.sleep(0.1)
            # update available capacity
            current_time = time.time()
            seconds_since_update = current_time - self.last_update_time
            self.available_request_capacity = min(
                self.available_request_capacity + openAiMessageHandler.max_requests_per_minute * seconds_since_update / 60.0,
                openAiMessageHandler.max_requests_per_minute * openAiMessageHandler.rate_limit_time_interval / 60,
            )
            self.available_token_capacity = min(
                self.available_token_capacity + openAiMessageHandler.max_tokens_per_minute * seconds_since_update / 60.0,
                openAiMessageHandler.max_tokens_per_minute * openAiMessageHandler.rate_limit_time_interval / 60,
            )
            self.last_update_time = current_time
            if (self.available_request_capacity >= 1
                    and self.available_token_capacity >= tokens):
                # update counters
                self.available_request_capacity -= 1
                self.available_token_capacity -= tokens
                request.attempts_left -= 1
                break

    @staticmethod
    def get_token_count(request): #returns number of tokens
        encoding = tiktoken.encoding_for_model("gpt-3.5-turbo")
        tokens_per_msg = 4
        token_count = 0
        for msg in request.messages:
            token_count += tokens_per_msg
            token_count += len(encoding.encode(msg.role))
            token_count += len(encoding.encode(msg.content))
        token_count += request.max_tokens
        return token_count

    def get_openai_response(self, request):
        openai.api_key = request.api_key

        data = {
            "messages": [
                {"role": "system", "content": request.sys_msg.content},
                {"role": "user", "content": request.usr_msg.content}
            ],
            "temperature": request.temp,
            "max_tokens": request.max_tokens,
            "model": "gpt-3.5-turbo"
        }
        try:
            response = openai.ChatCompletion.create(**data)
            return response['choices'][0]['message']['content']
        except openai.error.OpenAIError as err:
            self.retry_queue.put(request)
            print(f"An error occurred: {err}")

    def rabbitmq_callback(self, channel, method, properties, body):  # gets requests from rabbit queue to create request and puts them in queue
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
            max_tokens = message_data.get("maxTokens")

            user = Message("user", usr_msg)
            sys = Message("system", sys_msg)
            self.request_queue.put(Request(api_key, sys, user, temp, job_id, requestor_prio_id, prio_id, max_tokens))

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
    # message_handler.waitForLimitersTest()
