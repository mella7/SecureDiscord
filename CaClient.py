from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
#from cryptography.hazmat.primitives import hashe
from cryptography import x509
from cryptography.x509.oid import NameOID
import pika
import os

class CaClient:
    # Initializes a CaClient object with the given username.
    def __init__(self, username):
        self.username = username

    # Generates a 3072-bit RSA private key, saves it in 'client_key.pem', and returns the key.
    def generateKey(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
            backend=default_backend()
        )
        with open('client_key.pem', 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        return private_key

    # Generates a Certificate Signing Request (CSR) using the private key and returns the CSR data.
    def generateCertRequest(self):
        private_key = self.generateKey()
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Tek Up'),
                x509.NameAttribute(NameOID.COMMON_NAME, self.username),
            ])
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        with open('client_csr.pem', 'wb') as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        return csr.public_bytes(serialization.Encoding.PEM)

    # Establishes a connection to RabbitMQ, declares necessary exchanges, queues, and starts consuming messages.
    def connect(self):
        connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        channel = connection.channel()
        channel.exchange_declare(exchange='cert_exchange', exchange_type='direct')
        result = channel.queue_declare('', exclusive=True)
        queue_name = result.method.queue
        channel.queue_bind(exchange='cert_exchange', queue=queue_name)
        channel.basic_consume(queue=queue_name, on_message_callback=self.callback, auto_ack=True)
        channel.start_consuming()

    # Sends a message to RabbitMQ with the specified action and data.
    def send(self, action, data):
        connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        channel = connection.channel()
        channel.exchange_declare(exchange='cert_exchange', exchange_type='direct')
        channel.basic_publish(exchange='cert_exchange', routing_key='cert_req_queue', body=f'{action}:{data}')
        connection.close()

    # Configures the client to receive messages from RabbitMQ and starts consuming messages.
    def receive(self):
        connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        channel = connection.channel()
        channel.exchange_declare(exchange='cert_exchange', exchange_type='direct')
        result = channel.queue_declare('', exclusive=True)
        queue_name = result.method.queue
        channel.queue_bind(exchange='cert_exchange', queue=queue_name)
        channel.basic_consume(queue=queue_name, on_message_callback=self.callback, auto_ack=True)
        channel.start_consuming()

    # Callback function called when a message is received. Handles actions based on received data.
    '''
    def callback(self, ch, method, properties, body):
        action, data = body.split(':')
        if action == 'request':
            # ...
            pass
        elif action == 'verify':
            # ...
            pass
    '''

    # Generates a certificate request, sends it to RabbitMQ, and starts consuming messages.
    def request_cert(self):
        cert_request = self.generateCertRequest()
        self.send('request', cert_request)
        self.receive()

    # Loads a local certificate, sends its data to RabbitMQ for verification, and starts consuming messages.
    def verify_cert(self):
        cert_data = self.handle_cert_local('client_cert.pem')
        self.send('verify', cert_data)
        self.receive()

    # Handles a local certificate, prints certificate information, and returns certificate data.
    def handle_cert_local(self, CERT_PATH):
        if os.path.exists(CERT_PATH):
            with open(CERT_PATH, 'rb') as f:
                cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                print(f"Issuer: {cert.issuer}")
                print(f"Version: {cert.version}")
                print(f"Subject: {cert.subject}")
                return cert_data
        else:
            print(f"Error: Certificate file not found at {CERT_PATH}")
            return None

    # Handles certificate data, prints certificate information, and returns the loaded certificate.
    def handle_cert(self, certifData):
        if certifData:
            cert = x509.load_pem_x509_certificate(certifData, default_backend())
            print(f"Issuer: {cert.issuer}")
            print(f"Version: {cert.version}")
            print(f"Subject: {cert.subject}")
            return cert
        else:
            print("Error: Certificate data is empty")
            return None


#client = CaClient(username='mella7')
#client.request_cert()
#client.verify_cert()
