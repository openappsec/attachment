#!/usr/bin/python3
import base64
import os
import argparse
import subprocess
from shutil import which
from pathlib import Path

def generate_keys(service, namespace, directory="generated"):
	"Generate key material and configuration for Kubernetes admission controllers"

	if not which("openssl"):
		raise click.UsageError("Unable to detect the openssl CLI tool on the path")

	if not os.path.exists(directory):
		os.makedirs(directory)

	print("==> Generating CA")

	command = """openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -days 100000 -out ca.crt -subj '/CN=admission_ca'"""

	subprocess.run(command, cwd=directory, shell=True, stderr=subprocess.DEVNULL)

	print("==> Creating configuration")

	with open(os.path.sep.join((directory, "server.conf")), "w") as f:
		f.write(
			"""[req]
default_bits   = 2048
req_extensions = v3_req
distinguished_name = req_distinguished_name
req_extensions     = req_ext
prompt = no
[ req_distinguished_name ]
CN  = {service}.{namespace}.svc
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
[ req_ext ]
subjectAltName = @alt_names
[alt_names]
DNS.1 = {service}
DNS.2 = {service}.{namespace}
DNS.3 = {service}.{namespace}.svc
""".format(service = service, namespace = namespace)
		)

	print("==> Generating private key and certificate")

	address = "{}.{}.svc".format(service, namespace)

	command = """openssl genrsa -out server.key 2048
openssl req -out server.csr -newkey rsa:2048 -nodes -keyout server.key -config server.conf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 100000 -extensions req_ext -extfile server.conf""".format(
		ADDRESS = address
	)

	subprocess.run(command, cwd=directory, shell=True, stderr=subprocess.DEVNULL)

	print("==> Key material generated")

	with open(os.path.sep.join((directory, "ca.crt")), "rb") as f:
		ca_cert = f.read()
		print("Use this as the caBundle:")
		print(base64.b64encode(ca_cert).decode("ascii"))

	print("==> Command to create secret")
	print("Run this to upload the key material to a Kubernetes secret")
	print()

	print(
		"kubectl --namespace={0} create secret tls {1}-certs --cert={2}/server.crt --key={2}/server.key".format(
			namespace, service, directory
		)
	)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description = 'Check Point Webhooks K8s Webhook Keygen')
	parser.add_argument("namespace", help = "Destination namespace")

	args = parser.parse_args()

	generate_keys("envoy-injector", args.namespace)