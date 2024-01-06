import pika
from os import path
import datetime
# verifying function doesn't exist in cryptography module
from OpenSSL.crypto import verify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

'''
Steps
  1st: Generate key / load it
  2nd: Receive the certificate request / load it (network)
  3rd: Check and sign it
  4th: Send it back / save it to disk
'''

CA_CERT_PATH = 'certificate_ca.pem'
CA_KEY_PATH = 'key_ca.pem'
cert = None
key = None

def generate_or_load():
    global cert
    global key

    if path.isfile(CA_CERT_PATH) and path.exists(CA_CERT_PATH) and path.isfile(CA_KEY_PATH) and path.exists(CA_KEY_PATH):
        # load files
        print('Loading!')
        cert = x509.load_pem_x509_certificate(
            open(CA_CERT_PATH, 'rb').read(), default_backend()
        )
        print(cert)
        key = serialization.load_pem_private_key(
            open(CA_KEY_PATH, 'rb').read(), password=None, backend=default_backend()
        )
        
    else:
        print('Generating!')
        
        # generate key and self-signed cert
        key = rsa.generate_private_key(
            public_exponent=65537, 
            key_size=3072, 
            backend=default_backend()
        ) 
        
        # Save it to disk
        with open(CA_KEY_PATH, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        ) 
            
        # Making a self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tunis"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"tekup"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureDiscord"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"SecureDiscord"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=9125)
        ).sign(
            key, hashes.SHA256(), default_backend()
        )

        # Write the certificate to the disk.
        with open(CA_CERT_PATH, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    return (key, cert)

def handle_cert_req(CSR_PATH):
    if path.exists(CSR_PATH) and path.isfile(CSR_PATH):
        # loading certification request
        print('Handling request')
        csr = x509.load_pem_x509_csr(open(CSR_PATH, 'rb').read(), default_backend())
        cert_client = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            cert.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # The CA certificate will be valid for 7 days
            datetime.datetime.utcnow() + datetime.timedelta(days=7)
        )
        for ext in csr.extensions:
            cert_client.add_extension(ext.value, ext.critical)

        cert_client = cert_client.sign(key, hashes.SHA256(), default_backend())
        with open('client_cert.pem', 'wb') as f:
            f.write(cert_client.public_bytes(serialization.Encoding.PEM))
    else:
        print('No Request to handle')

def handle_req(reqData, cert):
    csr = x509.load_pem_x509_csr(reqData, default_backend())

    cert_client = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=7)
    )

    for ext in csr.extensions:
        cert_client.add_extension(ext.value, ext.critical)

    cert_client = cert_client.sign(key, hashes.SHA256(), default_backend())
    return cert_client.public_bytes(serialization.Encoding.PEM).decode()

def handle_cert(data):
    if data:
        cert = x509.load_pem_x509_certificate(data, default_backend())
        # print(cert.issuer, cert.version, cert.subject)
        return cert
    else:
        print('There is no certification')
        return None

# First step is created a ROOT certificate (self signed certificate for the authority)
# generate_or_load()

# Second is handling any certificate request and sign it using the ROOT certificate
# andle_cert_req('client_csr.pem')

class CaServer:
    def generate_authority_key(self):
        self.ca_key, self.ca_cert = generate_or_load()
        self.ca_pubkey = self.ca_key.public_key()

    def connect(self):
        self.generate_authority_key()
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters(host='192.168.219.129')
            )
        self.channel = self.connection.channel()
        self.receive()

    def send(self, client_queue, action, data):
        self.channel.exchange_declare(exchange='cert_exchange', exchange_type='direct')
        self.channel.queue_declare(queue=client_queue, durable=True)

        message = f"{action}::{data}"
        self.channel.basic_publish(
            exchange='cert_exchange',
            routing_key=client_queue,
            body=message
        )
        print(f'Server sent cert to {client_queue}')

    def receive(self):
        self.channel.queue_declare(queue='cert_req_queue', durable=True)

        def callback(ch, method, properties, body):
            client_queue, action, data = body.decode().split('::')

            if action == 'request':
                print(f'Server got cert request from {client_queue}')
                data = data.encode()
                certdata = handle_req(data, self.ca_cert)
                self.send(client_queue, 'certif', certdata)
                
            if action == 'verify':
                print(f'Server got verifying from {client_queue}')
                certif = handle_cert(data.encode())
                print(certif)
                result = ""
                try:
                    result = self.ca_pubkey.verify(
                        certif.signature,
                        certif.tbs_certificate_bytes,
                        # Depends on the algorithm used to create the certificate
                        padding.PKCS1v15(),
                        certif.signature_hash_algorithm,
                    )
                    result = "Ok"
                except Exception:
                    result = "Not Verified"
                finally:
                    self.send(client_queue, 'verify', result)

            ch.basic_ack(delivery_tag=method.delivery_tag)

        self.channel.basic_consume(
            queue='cert_req_queue', on_message_callback=callback)
        print('Server Started!! Listening')
        self.channel.start_consuming()

server = CaServer()
server.connect()
