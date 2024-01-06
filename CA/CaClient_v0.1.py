from os import path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import pika

'''
Steps:
  1st: Creating an RSA key
  2nd: Creating a Certificate Request
  3rd: Making a RabbitMQ connection
  4th: Create a receiving queue with a random name bound to cert_exchange
  5th: Send the cert req with queue_name to cert_req_queue
  6th: Get the certif back
'''

def handle_local_certificate(cert_path):
    if path.exists(cert_path) and path.isfile(cert_path):
        cert_client = x509.load_pem_x509_certificate(open(cert_path, 'rb').read(), default_backend())
        print(dir(cert_client))
        print(cert_client.issuer, cert_client.version, cert_client.subject)
        return cert_client
    else:
        print("There is no certificate issued for the client")
        return None

def handle_certificate(cert_data):
    if cert_data:
        cert = x509.load_pem_x509_certificate(cert_data.encode(), default_backend())
        print(cert.issuer, cert.version, cert.subject)
        return cert
    else:
        print('There is no certification')
        return None

class ChatSecurityClient:
    def __init__(self, username):
        self.username = username

    def generate_key(self):
        # Create private Key
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
        # Save it to disk
        with open("./client_key.pem", "wb") as f:
            f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                       format=serialization.PrivateFormat.TraditionalOpenSSL,
                                       encryption_algorithm=serialization.NoEncryption()))
        return key

    def generate_cert_request(self):
        key = self.generate_key()
        # Create a certificate request
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureDiscord"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"User:" + str(self.username)),
        ])).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).sign(
            key, hashes.SHA256(), default_backend())
        # Write our CSR out to disk.
        with open("./client_csr.pem", "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        return csr.public_bytes(serialization.Encoding.PEM).decode()

    def connect(self):
        self.connection = pika.BlockingConnection(pika.ConnectionParameters(host='192.168.219.129'))
        self.channel = self.connection.channel()
        self.receive()

    def send(self, action, data):
        self.channel.queue_declare(queue='cert_req_queue', durable=True)
        message = self.queue_name + '::' + action + '::' + str(data)

        self.channel.basic_publish(
            exchange='',
            routing_key='cert_req_queue',
            body=message
        )
        print('Client sends request with queue ' + str(self.queue_name))

    def receive(self):
        self.channel.exchange_declare(exchange='cert_exchange', exchange_type='direct')
        result = self.channel.queue_declare(queue='', exclusive=True)
        self.queue_name = result.method.queue[4:]
        self.channel.queue_bind(exchange='cert_exchange', queue=result.method.queue, routing_key=self.queue_name)

        def callback(ch, method, properties, body):
            action, data = body.decode().split('::')

            if action == 'certif':
                print('Client ' + str(self.queue_name), ' gets  certif ' + str(data[:15]))
                client_cert = handle_certificate(data)
                # Save it to disk
                with open("CA/client_cert.pem", "wb") as f:
                    f.write(client_cert.public_bytes(serialization.Encoding.PEM))

                self.cert = data
                self.channel.close()
                self.connection.close()
            if action == 'verify':
                print('Cert Verification result', str(data))
                self.cert_is_ok = data
                self.channel.close()
                self.connection.close()

        self.channel.basic_consume(queue=result.method.queue, on_message_callback=callback, auto_ack=True)

    def request_cert(self):
        data = self.generate_cert_request()
        self.send('request', data)
        self.channel.start_consuming()

    def verify_cert(self):
        cert_client = handle_local_certificate('./client_cert.pem')
        cert = cert_client.public_bytes(serialization.Encoding.PEM).decode()
        print(cert)
        print(cert_client)
        self.send('verify', cert)
        self.channel.start_consuming()

# client = ChatSecurityClient("USERNAME")
# client.connect()
# client.request_cert()
# result = handle_local_certificate('CA/client_cert.pem')
# print(result != None)

# client = ChatSecurityClient("USERNAME")
# client.connect()
# client.verify_cert()
# print(client.cert_is_ok)
