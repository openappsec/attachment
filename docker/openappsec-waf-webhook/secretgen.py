#!/usr/bin/python

import os
import base64
import kubernetes.client
from kubernetes.client.rest import ApiException
from kubernetes import client, config
from pprint import pprint

# Key generation script
import keygen

SERVICE_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/"
API_SERVER = "https://kubernetes.default.svc"

GENERATED_CERTS_FOLDER = "/certs/"

config.load_incluster_config()

def getToken():
	with open(os.path.sep.join((SERVICE_PATH, "token")), "r") as f:
		return f.read()

def main():
	# First, generate keys
	keygen.generate_keys("openappsec-waf-webhook-svc", os.environ["K8S_NAMESPACE"], GENERATED_CERTS_FOLDER)

	found = None

	api_instance = client.AdmissionregistrationV1Api()

	try:
		api_response = api_instance.list_mutating_webhook_configuration()

		for result in api_response.items:
			print(result.metadata.name)
			if "openappsec-waf.injector" in result.metadata.name:
				pprint(result)
				found = result
				break

		if found is None:
			raise Exception("Could not find webhook")

		# Change the CA file
		with open(os.path.sep.join((GENERATED_CERTS_FOLDER, "ca.crt")), "rb") as f:
			cert = base64.b64encode(f.read()).decode("utf-8")

		print("CA Cert:", cert)

		# Update cert
		for webhook in found.webhooks:
			if "openappsec-waf.injector" in webhook.name:
				webhook.client_config.ca_bundle = cert;


		# Patch
		response = api_instance.patch_mutating_webhook_configuration(found.metadata.name, found, pretty = "true")

		pprint(response)
	except ApiException as e:
		print("Exception when calling AdmissionregistrationApi->get_api_group: %s\n" % e)

if __name__ == "__main__":
	main()