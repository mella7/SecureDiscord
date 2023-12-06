import pika
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

class CaServer:
    def __init__(self):
        self.ca_cert_path = 'CA_cert.pem'
        self.ca_key_path = 'CA_key.pem'
        self.ca_pubkey_path = 'CA_pubkey.pem'
        self.cert_exchange = 'cert_exchange'
        self.cert_req_queue = 'cert_req_queue'

    # generate_or_load: Generates or loads CA key and certificate.
    # If files exist, loads them; else, generates new ones.
    # Returns a tuple containing private key and certificate.
    def generate_or_load(self):
        if os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path):
            with open(self.ca_key_path, 'rb') as key_file:
                ca_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )

            with open(self.ca_cert_path, 'rb') as cert_file:
                ca_cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())

        else:
            ca_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tunis"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Tunis"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TekUp"),
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                ca_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,
            ).sign(ca_key, hashes.SHA256(), default_backend())

            with open(self.ca_key_path, 'wb') as key_file:
                key_file.write(ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open(self.ca_cert_path, 'wb') as cert_file:
                cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

        self.ca_key = ca_key
        self.ca_cert = cert
        self.ca_pubkey = ca_key.public_key()

        return ca_key, cert

    # handle_cert_req: Handles client certificate requests.
    # Loads CSR, signs with CA key, and writes client certificate.
    def handle_cert_req(self, CSR_PATH):
        # ...
        pass

    # handle_req: Handles certificate requests using provided data and CA certificate.
    # Builds and signs a client certificate, returning it as a PEM-encoded string.
    def handle_req(self, reqData, cert):
        # ...
        pass
    
    # handle_cert: Handles certificate data.
    # Loads certificate from PEM-encoded string and returns it.
    def handle_cert(self, data):
        # ...
        pass

    # generate_authority_key: Generates or loads CA private key and certificate.
    # If files exist, loads them; else, generates new ones.
    # Stores private key in self.ca_key, certificate in self.ca_cert, and public key in self.ca_pubkey.
    def generate_authority_key(self):
        ca_key, ca_cert = self.generate_or_load()
        self.ca_key = ca_key
        self.ca_cert = ca_cert

    # connect: Initializes RabbitMQ connection and calls generate_authority_key.
    # Also calls receive to configure server for handling certificate requests.
    def connect(self):
        credentials = pika.PlainCredentials('guest', 'guest')
        connection_params = pika.ConnectionParameters('localhost', credentials=credentials)
        connection = pika.BlockingConnection(connection_params)
        channel = connection.channel()

        channel.exchange_declare(exchange=self.cert_exchange, exchange_type='direct')
        channel.queue_declare(queue=self.cert_req_queue)
        channel.queue_bind(exchange=self.cert_exchange, queue=self.cert_req_queue)

        channel.basic_consume(queue=self.cert_req_queue, on_message_callback=self.callback, auto_ack=True)
        channel.start_consuming()

    # send: Sends messages to a client via RabbitMQ.
    # Declares an exchange and sends messages to a specified client queue.
    def send(self, client_queue, action, data):
        # ...
        pass

    # receive: Configures RabbitMQ to receive messages.
    # Defines a callback function for processing incoming messages.
    def receive(self):
        # ...
        pass

    # callback: Callback function for received messages.
    # Processes requests, signing and returning certificates or verifying received certificates.
    def callback(self, ch, method, properties, body):
        # ...
        pass


# server = CaServer()
# server.generate_authority_key()
# server.connect()
