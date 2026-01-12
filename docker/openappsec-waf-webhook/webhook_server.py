import os
import json
import logging
import base64
import secretgen
import sys
import re
import yaml
import requests
from kubernetes import client, config
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

# Read agent image and tag from environment variables
AGENT_IMAGE = os.getenv('AGENT_IMAGE', 'ghcr.io/openappsec/agent')
AGENT_TAG = os.getenv('AGENT_TAG', 'latest')
AGENT_CPU = os.getenv('AGENT_CPU', '200m')
PROXY_KIND = os.getenv('PROXY_KIND', 'istio')
INIT_CONTAINER_IMAGE = os.getenv('INIT_CONTAINER_IMAGE', 'ghcr.io/openappsec/openappsec-envoy-filters')
INIT_CONTAINER_TAG = os.getenv('INIT_CONTAINER_TAG', 'latest')
ISTIOD_PORT = os.getenv('ISTIOD_PORT', '15014')
RELEASE_NAMESPACE = os.getenv('K8S_NAMESPACE', 'envoy-gateway-system')
FULL_AGENT_IMAGE = f"{AGENT_IMAGE}:{AGENT_TAG}"
FULL_INIT_CONTAINER_IMAGE = f"{INIT_CONTAINER_IMAGE}:{INIT_CONTAINER_TAG}"

config.load_incluster_config()

def is_istio_agent():
    """Check if the current agent kind is Istio"""
    return PROXY_KIND.lower() == "istio"

def is_envoy_gateway_agent():
    """Check if the current agent kind is Envoy Gateway"""
    return PROXY_KIND.lower() == "envoy_gateway"

def is_envoy_based_proxy_agent():
    """Check if the current agent kind is Istio or Envoy Gateway"""
    return is_istio_agent() or is_envoy_gateway_agent()

def configure_logging():
    # Read the DEBUG_LEVEL from environment variables, defaulting to WARNING
    DEBUG_LEVEL = os.getenv('DEBUG_LEVEL', 'WARNING').upper()

    # Map the string value of DEBUG_LEVEL to actual logging level
    logging_levels = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }

    # Set the logging level based on the environment variable
    log_level = logging_levels.get(DEBUG_LEVEL, logging.INFO)

    # Configure Flask's logger to handle the specified logging level
    handler = logging.StreamHandler()
    handler.setLevel(log_level)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    if app.logger.hasHandlers():
        app.logger.handlers.clear()

    app.logger.addHandler(handler)
    app.logger.setLevel(log_level)

# The sidecar container spec with configurable image
def get_sidecar_container():
    app.logger.debug("Entering get_sidecar_container()")
    token = os.getenv("TOKEN")
    custom_fog_enabled = os.getenv("CUSTOM_FOG_ENABLED") == "true"  # Check if it's set to "true"
    fog_address = os.getenv("FOG_ADDRESS")
    registered_server = os.getenv("REGISTERED_SERVER")
    appsec_proxy = os.getenv("APPSEC_PROXY")
    config_map_ref = os.getenv("CONFIG_MAP_REF")
    secret_ref = os.getenv("SECRET_REF")
    persistence_enabled = os.getenv("APPSEC_PERSISTENCE_ENABLED", "false").lower() == "true"

    if is_envoy_based_proxy_agent():
        volume_mounts = [
            {"name": "envoy-attachment-shared", "mountPath": "/envoy/attachment/shared/"},
            {"name": "advanced-model", "mountPath": "/advanced-model"}
        ]
    else:
        volume_mounts = [
            {"name": "advanced-model", "mountPath": "/advanced-model"}
        ]

    if persistence_enabled:
        volume_mounts.extend([
            {"name": "open-appsec-conf", "mountPath": "/etc/cp/conf"},
            {"name": "open-appsec-data", "mountPath": "/etc/cp/data"}
        ])

    args = []
    if token:
        args.extend(["--token", token])
    else:
        args.append("--hybrid-mode")

    if custom_fog_enabled and fog_address:
        args.extend(["--fog", fog_address])

    if appsec_proxy:
        args.extend(["--proxy", appsec_proxy])

    optional_env_vars = {
        "AGENT_TOKEN": os.getenv("AGENT_TOKEN"),
        "user_email": os.getenv("user_email"),
        "appsecClassName": os.getenv("appsecClassName"),
        "SHARED_STORAGE_HOST": os.getenv("SHARED_STORAGE_HOST"),
        "LEARNING_HOST": os.getenv("LEARNING_HOST"),
        "TUNING_HOST": os.getenv("TUNING_HOST"),
        "LOCAL_TUNING_ENABLED": os.getenv("LOCAL_TUNING_ENABLED"),
        "PLAYGROUND": os.getenv("PLAYGROUND"),
        "CRDS_SCOPE": os.getenv("CRDS_SCOPE"),
    }

    env = [
        {"name": "registered_server", "value": registered_server}
    ]

    for var_name, var_value in optional_env_vars.items():
        if var_value is not None:
            env.append({"name": var_name, "value": var_value})

    sidecar = {
        "name": "open-appsec-nano-agent",
        "image": FULL_AGENT_IMAGE,
        "imagePullPolicy": "Always",
        "command": ["/cp-nano-agent"],
        "args": args,
        "env": env,
        "volumeMounts": volume_mounts,
        "resources": {
            "requests": {
                "cpu": AGENT_CPU
            }
        },
        "envFrom": [
            {
                "configMapRef": {
                    "name": config_map_ref
                }
            },
            {
                "secretRef": {
                    "name": secret_ref
                }
            }
        ],
        "securityContext": {
            "runAsNonRoot": False,
            "runAsUser": 0
        },
        "terminationMessagePath": "/dev/termination-log",
        "terminationMessagePolicy": "File"
    }
    app.logger.debug(f"Sidecar container spec: {sidecar}")
    app.logger.debug("Exiting get_sidecar_container()")
    return sidecar

def get_istio_version():
    url = f"http://istiod.istio-system:{ISTIOD_PORT}/version"
    response = requests.get(url)
    if response.status_code == 200:
        return response.text.strip().split('-')[0]
    else:
        raise Exception(f"Failed to get Istio version: {response.status_code}")

def get_envoy_sha(istio_version):
    url = f"https://raw.githubusercontent.com/istio/proxy/{istio_version}/WORKSPACE"
    response = requests.get(url)
    if response.status_code == 200:
        match = re.search(r'ENVOY_SHA = \"([a-f0-9]+)\"', response.text)
        if match:
            return match.group(1)
        else:
            raise Exception("Envoy SHA not found in WORKSPACE file")
    else:
        raise Exception(f"Failed to get WORKSPACE file: {response.status_code}")

def get_envoy_version(envoy_sha):
    url = f"https://raw.githubusercontent.com/envoyproxy/envoy/{envoy_sha}/VERSION.txt"
    response = requests.get(url)
    if response.status_code == 200:
        version = response.text.strip()
        match = re.search(r'(\d+\.\d+)', version)
        if match:
            return match.group(1)
        else:
            raise Exception("Failed to extract major.minor version")
    else:
        raise Exception(f"Failed to get Envoy version: {response.status_code}")

def get_envoy_gateway_version(containers):
    for container in containers:
        if container.get('name') == 'envoy':
            image = container.get('image', '')
            app.logger.debug(f"Found envoy container with image: {image}")

            match = re.search(r':v?(\d+\.\d+)(?:\.\d+)?', image)
            if match:
                version = match.group(1)
                app.logger.info(f"Extracted Envoy version from container image: {version}")
                return version
            else:
                raise Exception(f"Could not parse version from image: {image}")

    raise Exception("Envoy container not found in pod spec")

def get_init_container(containers=None):
    # Define the initContainer you want to inject
    try:
        if is_istio_agent():
            istio_version = get_istio_version()
            app.logger.debug(f"Istio Version: {istio_version}")

            envoy_sha = get_envoy_sha(istio_version)
            app.logger.debug(f"Envoy SHA: {envoy_sha}")

            envoy_version = get_envoy_version(envoy_sha)
        elif is_envoy_gateway_agent() and containers:
            envoy_version = get_envoy_gateway_version(containers)
    except Exception as e:
        app.logger.warning(f"Failed to detect Envoy version: {e}. Using default: {envoy_version}")

    app.logger.info(f"Envoy Version: {envoy_version}")

    init_container = {
        "name": "prepare-attachment",
        "image": FULL_INIT_CONTAINER_IMAGE,
        "imagePullPolicy": "Always",
        "command": [
            "sh", "-c",
            f"mkdir -p /envoy/attachment/shared && cp -r /envoy/attachment/lib* /envoy/attachment/shared && cp /envoy/attachment/versions/{envoy_version}/lib* /envoy/attachment/shared"
        ],
        "volumeMounts": [
            {
                "mountPath": "/envoy/attachment/shared",
                "name": "envoy-attachment-shared"
            }
        ]
    }
    app.logger.debug(f"Init container spec: {init_container}")
    app.logger.debug("Exiting get_init_container()")
    return init_container

def get_volume_mount():
    app.logger.debug("Entering get_volume_mount()")
    volume_mount = {
        "name": "envoy-attachment-shared",
        "mountPath": "/usr/lib/attachment/"
    }
    app.logger.debug(f"Volume mount spec: {volume_mount}")
    app.logger.debug("Exiting get_volume_mount()")
    return volume_mount

def get_volume_definition():
    app.logger.debug("Entering get_volume_definition()")

    persistence_enabled = os.getenv("APPSEC_PERSISTENCE_ENABLED", "false").lower() == "true"

    if is_envoy_based_proxy_agent():
        volume_def = [
            {
                "name": "envoy-attachment-shared",
                "emptyDir": {}
            },
            {
                "name": "advanced-model",
                "configMap": {
                    "name": "advanced-model-config",
                    "optional": True
                }
            }
        ]
    else:
        volume_def = [
            {
                "name": "advanced-model",
                "configMap": {
                    "name": "advanced-model-config",
                    "optional": True
                }
            }
        ]

    if persistence_enabled:
        volume_def.extend([
            {
                "name": "open-appsec-conf",
                "persistentVolumeClaim": {
                    "claimName": "open-appsec-conf"
                }
            },
            {
                "name": "open-appsec-data",
                "persistentVolumeClaim": {
                    "claimName": "open-appsec-data"
                }
            }
        ])

    app.logger.debug(f"Volume definition: {volume_def}")
    app.logger.debug("Exiting get_volume_definition()")
    return volume_def

def add_env_if_not_exist(containers, container_name, patches):
    # Find the container by name
    container = next((c for c in containers if c.get('name') == container_name), None)

    if container:
        # Get the existing environment variables (if any)
        env_vars = container.get('env', None)

        if env_vars is None:
            # If no env variables exist, add an empty env array first
            patches.append({
                "op": "add",
                "path": f"/spec/containers/{containers.index(container)}/env",
                "value": []
            })

def add_env_variable_value_from(containers, container_name, env_var_name, env_value, patches, value_from):
    """Adds or updates a specified environment variable in a given container."""
    container_index = next((i for i, container in enumerate(containers) if container['name'] == container_name), None)

    if container_index is not None:
        env_vars = containers[container_index].get('env', [])
        existing_env_var = next((env for env in env_vars if env['name'] == env_var_name), None)

        if existing_env_var:
            env_var_patch = {
                "op": "replace",
                "path": f"/spec/containers/{container_index}/env/{env_vars.index(existing_env_var)}",
                "value": {"name": env_var_name, "valueFrom": value_from}
            }
            patches.append(env_var_patch)
            app.logger.debug(f"Updated {env_var_name} environment variable in {container_name} container to use valueFrom.")
        else:
            env_var_patch = {
                "op": "add",
                "path": f"/spec/containers/{container_index}/env/-",
                "value": {"name": env_var_name, "valueFrom": value_from}
            }
            patches.append(env_var_patch)
            app.logger.debug(f"Added {env_var_name} environment variable with valueFrom to {container_name} container.")
    else:
        app.logger.warning(f"{container_name} container not found; no environment variable modification applied.")

def add_env_variable(containers, container_name, env_var_name, env_value, patches):
    """Adds or updates a specified environment variable in a given container."""
    # Find the specified container by name
    container_index = next((i for i, container in enumerate(containers) if container['name'] == container_name), None)

    if container_index is not None:
        # Get the list of environment variables for the specified container
        env_vars = containers[container_index].get('env', [])

        # Find the specified environment variable if it exists
        existing_env_var = next((env for env in env_vars if env['name'] == env_var_name), None)

        # If the environment variable exists, handle it based on its name
        if existing_env_var:
            current_value = existing_env_var['value']

            if env_var_name == 'LD_LIBRARY_PATH':
                # For LD_LIBRARY_PATH, append env_value if not already present
                if env_value not in current_value:
                    new_value = f"{current_value}:{env_value}"
                    env_var_patch = {
                        "op": "replace",
                        "path": f"/spec/containers/{container_index}/env/{env_vars.index(existing_env_var)}/value",
                        "value": new_value
                    }
                    patches.append(env_var_patch)
                    app.logger.debug(f"Updated {env_var_name} environment variable in {container_name} container to new value.")
                else:
                    app.logger.debug(f"{env_var_name} already exists with the correct value; no changes made.")
            else:
                # For other environment variables, replace the value directly
                env_var_patch = {
                    "op": "replace",
                    "path": f"/spec/containers/{container_index}/env/{env_vars.index(existing_env_var)}/value",
                    "value": env_value
                }
                patches.append(env_var_patch)
                app.logger.debug(f"Replaced {env_var_name} environment variable in {container_name} container with new value.")

        else:
            # Add the environment variable if it does not exist
            env_var_patch = {
                "op": "add",
                "path": f"/spec/containers/{container_index}/env/-",
                "value": {
                    "name": env_var_name,
                    "value": env_value
                }
            }
            patches.append(env_var_patch)
            app.logger.debug(f"Added {env_var_name} environment variable to {container_name} container.")
    else:
        app.logger.warning(f"{container_name} container not found; no environment variable modification applied.")

def remove_env_variable(containers, container_name, env_var_name, patches):
    """Removes a specified environment variable from a given container if it exists."""
    # Find the specified container by name
    container_index = next((i for i, container in enumerate(containers) if container['name'] == container_name), None)

    if container_index is not None:
        # Get the list of environment variables for the specified container
        env_vars = containers[container_index].get('env', [])

        # Check if the specified environment variable exists
        env_var_exists = any(env['name'] == env_var_name for env in env_vars)

        # Remove the environment variable if it exists
        if env_var_exists:
            # Find the index of the specified environment variable in the env array
            env_var_index = next(i for i, env in enumerate(env_vars) if env['name'] == env_var_name)
            patches.append({
                "op": "remove",
                "path": f"/spec/containers/{container_index}/env/{env_var_index}"
            })
            app.logger.debug(f"Removed {env_var_name} environment variable from {container_name} container.")
        else:
            app.logger.debug(f"{env_var_name} does not exist, nothing to remove.")
    else:
        app.logger.warning(f"{container_name} container not found; no environment variable modification applied.")

def ensure_envoy_gateway_extension_apis():
    """Ensure the envoy-gateway-config ConfigMap has extensionApis.enableEnvoyPatchPolicy enabled"""
    v1 = client.CoreV1Api()

    try:
        config_map = v1.read_namespaced_config_map(
            name="envoy-gateway-config",
            namespace=RELEASE_NAMESPACE
        )

        config_data_str = config_map.data.get('envoy-gateway.yaml', '')
        try:
            config_obj = yaml.safe_load(config_data_str)
        except yaml.YAMLError as e:
            app.logger.error(f"Failed to parse envoy-gateway.yaml: {e}")
            return

        # Check if extensionApis is already properly configured
        extension_apis = config_obj.get('extensionApis', {})
        if extension_apis.get('enableEnvoyPatchPolicy') is True:
            app.logger.info("EnvoyPatchPolicy already enabled in envoy-gateway-config")
            return

        # Ensure extensionApis exists and add/update enableEnvoyPatchPolicy
        if 'extensionApis' not in config_obj or config_obj['extensionApis'] is None:
            config_obj['extensionApis'] = {}

        config_obj['extensionApis']['enableEnvoyPatchPolicy'] = True

        config_data_updated = yaml.dump(config_obj, default_flow_style=False, sort_keys=False)
        config_map.data['envoy-gateway.yaml'] = config_data_updated
        v1.replace_namespaced_config_map(
            name="envoy-gateway-config",
            namespace=RELEASE_NAMESPACE,
                        body=config_map
        )
        app.logger.info("Updated envoy-gateway-config to enable EnvoyPatchPolicy")

    except client.exceptions.ApiException as e:
        if e.status == 404:
            app.logger.warning("envoy-gateway-config ConfigMap not found")
        else:
            app.logger.error(f"Failed to update envoy-gateway-config: {e}")

def create_or_update_envoy_patch_policy(name, gateway_name, gateway_namespace):
    """Create or update EnvoyPatchPolicy for Envoy Gateway"""
    api = client.CustomObjectsApi()

    listener_name = f"{gateway_namespace}/{gateway_name}/http"

    # Define the EnvoyPatchPolicy specification
    envoy_patch_policy_spec = {
        "apiVersion": "gateway.envoyproxy.io/v1alpha1",
        "kind": "EnvoyPatchPolicy",
        "metadata": {
            "name": name,
            "namespace": gateway_namespace,
            "labels": {
                "owner": "waf"
            }
        },
        "spec": {
            "targetRef": {
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "name": gateway_name
            },
            "type": "JSONPatch",
            "jsonPatches": [
                {
                    "type": "type.googleapis.com/envoy.config.listener.v3.Listener",
                    "name": listener_name,
                    "operation": {
                        "op": "add",
                        "path": "/default_filter_chain/filters/0/typed_config/http_filters/0",
                        "value": {
                            "name": "envoy.filters.http.golang",
                            "typed_config": {
                                "@type": "type.googleapis.com/envoy.extensions.filters.http.golang.v3alpha.Config",
                                "library_id": "cp_nano_filter",
                                "plugin_name": "cp_nano_filter",
                                "library_path": "/usr/lib/attachment/libenvoy_attachment.so",
                                "plugin_config": {
                                    "@type": "type.googleapis.com/xds.type.v3.TypedStruct",
                                    "value": {
                                        "prefix_localreply_body": "Configured local reply from go"
                                    }
                                }
                            }
                        }
                    }
                }
            ]
        }
    }

    # Check if the EnvoyPatchPolicy exists
    try:
        existing_policy = api.get_namespaced_custom_object(
            group="gateway.envoyproxy.io",
            version="v1alpha1",
            namespace=gateway_namespace,
            plural="envoypatchpolicies",
            name=name
        )

        # Compare targetRef
        existing_target = existing_policy.get("spec", {}).get("targetRef", {})
        new_target = envoy_patch_policy_spec["spec"]["targetRef"]

        if existing_target == new_target:
            app.logger.info(f"EnvoyPatchPolicy '{name}' already exists with matching target.")
            return
        else:
            # Update the existing EnvoyPatchPolicy
            existing_policy["spec"] = envoy_patch_policy_spec["spec"]
            api.replace_namespaced_custom_object(
                group="gateway.envoyproxy.io",
                version="v1alpha1",
                namespace=gateway_namespace,
                plural="envoypatchpolicies",
                name=name,
                body=existing_policy
            )
            app.logger.info(f"EnvoyPatchPolicy '{name}' updated successfully.")
            return

    except client.exceptions.ApiException as e:
        if e.status == 404:
            # EnvoyPatchPolicy doesn't exist, proceed with creation
            api.create_namespaced_custom_object(
                group="gateway.envoyproxy.io",
                version="v1alpha1",
                namespace=gateway_namespace,
                plural="envoypatchpolicies",
                body=envoy_patch_policy_spec
            )
            app.logger.info(f"EnvoyPatchPolicy '{name}' created successfully.")
        else:
            app.logger.error(f"Failed to create/update EnvoyPatchPolicy: {e}")

def remove_envoy_patch_policy_by_gateway(gateway_namespace, gateway_name):
    """Remove EnvoyPatchPolicy by gateway name"""
    api = client.CustomObjectsApi()
    try:
        # List all EnvoyPatchPolicies in the namespace
        existing_policies = api.list_namespaced_custom_object(
            group="gateway.envoyproxy.io",
            version="v1alpha1",
            namespace=gateway_namespace,
            plural="envoypatchpolicies"
        )

        # Check if there is any EnvoyPatchPolicy targeting the gateway
        for item in existing_policies.get("items", []):
            target_ref = item["spec"].get("targetRef", {})
            if target_ref.get("name") == gateway_name and target_ref.get("kind") == "Gateway":
                # Delete the matching EnvoyPatchPolicy
                api.delete_namespaced_custom_object(
                    group="gateway.envoyproxy.io",
                    version="v1alpha1",
                    namespace=gateway_namespace,
                    plural="envoypatchpolicies",
                    name=item["metadata"]["name"],
                    body=client.V1DeleteOptions()
                )
                app.logger.info(f"EnvoyPatchPolicy '{item['metadata']['name']}' targeting gateway '{gateway_name}' deleted successfully.")
                return
        app.logger.info(f"No EnvoyPatchPolicy found targeting gateway '{gateway_name}'.")

    except client.exceptions.ApiException as e:
        app.logger.error(f"Failed to delete EnvoyPatchPolicy: {e}")

def create_or_update_envoy_filter(name, namespace, selector_label_name, selector_label_value):
    api = client.CustomObjectsApi()
    envoy_filter_spec = {
        "apiVersion": "networking.istio.io/v1alpha3",
        "kind": "EnvoyFilter",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "owner": "waf"
            }
        },
        "spec": {
            "workloadSelector": {
                "labels": {
                    selector_label_name: selector_label_value
                }
            },
            "configPatches": [
                {
                    "applyTo": "HTTP_FILTER",
                    "match": {
                        "context": "GATEWAY",
                        "listener": {
                            "filterChain": {
                                "filter": {
                                    "name": "envoy.filters.network.http_connection_manager"
                                }
                            }
                        }
                    },
                    "patch": {
                        "operation": "INSERT_BEFORE",
                        "value": {
                            "name": "envoy.filters.http.golang",
                            "typed_config": {
                                "@type": "type.googleapis.com/envoy.extensions.filters.http.golang.v3alpha.Config",
                                "library_id": "cp_nano_filter",
                                "library_path": "/usr/lib/attachment/libenvoy_attachment.so",
                                "plugin_name": "cp_nano_filter",
                                "plugin_config": {
                                    "@type": "type.googleapis.com/xds.type.v3.TypedStruct",
                                    "type_url": "type.googleapis.com/envoy.extensions.filters.http.golang.v3alpha.PluginConfig",
                                    "value": {
                                        "prefix_localreply_body": "Configured local reply from go"
                                    }
                                }
                            }
                        }
                    }
                }
            ]
        }
    }

    try:
        existing_envoy_filter = api.get_namespaced_custom_object(
            group="networking.istio.io",
            version="v1alpha3",
            namespace=namespace,
            plural="envoyfilters",
            name=name
        )

        # Compare workloadSelector labels
        existing_labels = existing_envoy_filter.get("spec", {}).get("workloadSelector", {}).get("labels", {})
        new_labels = envoy_filter_spec["spec"]["workloadSelector"]["labels"]

        if existing_labels == new_labels:
            app.logger.info(f"EnvoyFilter '{name}' already exists with matching selector labels.")
            return
        else:
            # Update the existing EnvoyFilter's workloadSelector labels
            existing_envoy_filter["spec"]["workloadSelector"]["labels"] = new_labels
            api.replace_namespaced_custom_object(
                group="networking.istio.io",
                version="v1alpha3",
                namespace=namespace,
                plural="envoyfilters",
                name=name,
                body=existing_envoy_filter
            )
            app.logger.info(f"EnvoyFilter '{name}' updated successfully with new selector labels.")
            return

    except client.exceptions.ApiException as e:
        if e.status == 404:
            # EnvoyFilter doesn't exist, proceed with creation
            api.create_namespaced_custom_object(
                group="networking.istio.io",
                version="v1alpha3",
                namespace=namespace,
                plural="envoyfilters",
                body=envoy_filter_spec
            )
            app.logger.info(f"EnvoyFilter '{name}' created successfully.")

def remove_envoy_filter_by_selector(namespace, selector_label_name, selector_label_value):
    api = client.CustomObjectsApi()
    try:
        # List all EnvoyFilters in the namespace
        existing_envoy_filters = api.list_namespaced_custom_object(
            group="networking.istio.io",
            version="v1alpha3",
            namespace=namespace,
            plural="envoyfilters"
        )

        # Check if there is any EnvoyFilter with the same selector labels
        for item in existing_envoy_filters.get("items", []):
            workload_selector = item["spec"].get("workloadSelector", {}).get("labels", {})
            if workload_selector.get(selector_label_name) == selector_label_value:
                # Delete the matching EnvoyFilter
                api.delete_namespaced_custom_object(
                    group="networking.istio.io",
                    version="v1alpha3",
                    namespace=namespace,
                    plural="envoyfilters",
                    name=item["metadata"]["name"],
                    body=client.V1DeleteOptions()
                )
                print(f"EnvoyFilter '{item['metadata']['name']}' with matching selector labels deleted successfully.")
                return
        print("No EnvoyFilter found with the specified selector labels.")

    except client.exceptions.ApiException as e:
        print(f"Failed to delete EnvoyFilter: {e}")

@app.route('/mutate', methods=['POST'])
def mutate():
    app.logger.debug("Received request to mutate deployment.")

    try:
        request_data = request.get_json()
        app.logger.debug("Admission Review Request: %s", json.dumps(request_data, indent=2))
    except Exception as e:
        app.logger.error("Failed to parse request JSON: %s", str(e))
        return Response(status=400)

    # Extract the UID and the object from the request
    uid = request_data.get('request', {}).get('uid', '')
    obj = request_data.get('request', {}).get('object', {})
    namespace = request_data.get("request", {}).get("namespace")
    app.logger.debug("Extracted UID: %s", uid)
    app.logger.debug("Extracted Object: %s", json.dumps(obj, indent=2))

    # Initialize patches
    patches = []

    # Extract deployment annotations and spec
    annotations = obj.get('metadata', {}).get('annotations', {})
    spec = obj.get('spec', {})
    app.logger.debug("Current annotations: %s", json.dumps(annotations, indent=2))
    app.logger.debug("Deployment spec: %s", json.dumps(spec, indent=2))

    # Check if the 'original-configuration' annotation already exists
    if 'original-configuration' not in annotations:
        app.logger.debug("Original configuration annotation not found, storing original spec.")
        # Store the original spec in an annotation as a JSON string
        original_spec_json = json.dumps(spec)
        patches.append({
            "op": "add",
            "path": "/metadata/annotations/original-configuration",
            "value": original_spec_json
        })
        app.logger.debug("Added original-configuration annotation patch: %s", patches[-1])

    # Extract containers and check if sidecar exists
    containers = obj.get('spec', {}).get('containers', [])
    init_containers = obj.get('spec', {}).get('initContainers', [])
    volumes = obj.get('spec', {}).get('volumes', [])
    app.logger.debug("Current containers in the pod: %s", json.dumps(containers, indent=2))
    sidecar_exists = any(container['name'] == 'open-appsec-nano-agent' for container in containers)
    init_container_exist = any(init_container['name'] == 'prepare-attachment' for init_container in init_containers)
    # Only check for envoy-attachment-shared volume if agent kind is Istio or Envoy Gateway
    volume_exist = any(volume['name'] == 'envoy-attachment-shared' for volume in volumes) if is_envoy_based_proxy_agent() else False
    app.logger.debug("Does sidecar 'open-appsec-nano-agent' exist? %s", sidecar_exists)
    app.logger.debug("Agent kind: %s", PROXY_KIND)

    # Determine if we should remove the injected data
    REMOVE_WAF = os.getenv('REMOVE_INJECTED_DATA', 'false').lower() == 'true'
    DEPLOY_FILTER = os.getenv('DEPLOY_ENVOY_FILTER', 'false').lower() == 'true'

    ISTIO_CONTAINER_NAME = os.getenv('ISTIO_CONTAINER_NAME', 'istio-proxy')
    ENVOY_GATEWAY_CONTAINER_NAME = os.getenv('ENVOY_GATEWAY_CONTAINER_NAME', 'envoy')
    ENVOY_BASED_PROXY_CONTAINER_NAME = ENVOY_GATEWAY_CONTAINER_NAME if is_envoy_gateway_agent() else ISTIO_CONTAINER_NAME
    GATEWAY_RESOURCE_NAME = os.getenv('GATEWAY_RESOURCE_NAME', 'eg')
    GATEWAY_RESOURCE_NAMESPACE = os.getenv('GATEWAY_RESOURCE_NAMESPACE', 'default')
    LIBRARY_PATH_VALUE = os.getenv('LIBRARY_PATH_VALUE', '/usr/lib/attachment')
    SELECTOR_LABEL_NAME = os.getenv("SELECTOR_LABEL_NAME")
    SELECTOR_LABEL_VALUE = os.getenv("SELECTOR_LABEL_VALUE")
    CONCURRENCY_CALC_VALUE = os.getenv('CONCURRENCY_CALC')
    CONFIG_PORT_VALUE = os.getenv('CONFIG_PORT')
    CONCURRENCY_NUMBER_VALUE = os.getenv('CONCURRENCY_NUMBER')
    if REMOVE_WAF:
        app.logger.debug("Removing injected sidecar and associated resources.")

        if is_envoy_based_proxy_agent():
            app.logger.debug(f"PROXY_KIND is {PROXY_KIND}, removing {PROXY_KIND}-specific components.")

            if DEPLOY_FILTER:
                if is_istio_agent() and SELECTOR_LABEL_NAME and SELECTOR_LABEL_VALUE:
                    remove_envoy_filter_by_selector(namespace, SELECTOR_LABEL_NAME, SELECTOR_LABEL_VALUE)
                elif is_envoy_gateway_agent():
                    remove_envoy_patch_policy_by_gateway(GATEWAY_RESOURCE_NAMESPACE, GATEWAY_RESOURCE_NAME)

            if ENVOY_BASED_PROXY_CONTAINER_NAME:
                if CONCURRENCY_NUMBER_VALUE:
                    remove_env_variable(containers, ENVOY_BASED_PROXY_CONTAINER_NAME, 'CONCURRENCY_NUMBER', patches)
                if CONFIG_PORT_VALUE:
                    remove_env_variable(containers, ENVOY_BASED_PROXY_CONTAINER_NAME, 'CONFIG_PORT', patches)
                if CONCURRENCY_CALC_VALUE:
                    remove_env_variable(containers, ENVOY_BASED_PROXY_CONTAINER_NAME, 'CONCURRENCY_CALC', patches)
                if LIBRARY_PATH_VALUE:
                    remove_env_variable(containers, ENVOY_BASED_PROXY_CONTAINER_NAME, 'LD_LIBRARY_PATH', patches)

            if 'shareProcessNamespace' in obj.get('spec', {}):
                patches.append({
                    "op": "remove",
                    "path": "/spec/shareProcessNamespace"
                })
                app.logger.debug("Removed shareProcessNamespace patch")
            else:
                app.logger.debug("shareProcessNamespace not found; no patch to remove it")

            if init_container_exist:
                for idx, init_container in enumerate(init_containers):
                    if init_container['name'] == 'prepare-attachment':
                        patches.append({
                           "op": "remove",
                           "path": f"/spec/initContainers/{idx}"
                        })
                        app.logger.debug(f"Removed init container patch: {patches[-1]}")
                        break
        else:
            app.logger.debug(f"PROXY_KIND is {PROXY_KIND}, skipping Istio-specific removal.")

            # For kong agents, set automountServiceAccountToken back to false
            if 'automountServiceAccountToken' in obj.get('spec', {}):
                patches.append({
                    "op": "replace",
                    "path": "/spec/automountServiceAccountToken",
                    "value": False
                })
                app.logger.debug("Set automountServiceAccountToken=false for kong agent removal")

        if sidecar_exists:
            for idx, container in enumerate(containers):
                volume_mounts = container.get('volumeMounts', [])
                if is_envoy_based_proxy_agent():
                    for idx_v, volume_mount in enumerate(volume_mounts):
                        if volume_mount['name'] == 'envoy-attachment-shared':
                            patches.append({
                               "op": "remove",
                               "path": f"/spec/containers/{idx}/volumeMounts/{idx_v}"
                            })
                            app.logger.debug(f"Removed volumeMount: {patches[-1]}")
                if container['name'] == 'open-appsec-nano-agent':
                    patches.append({
                       "op": "remove",
                       "path": f"/spec/containers/{idx}"
                    })
                    app.logger.debug(f"Removed sidecar container patch: {patches[-1]}")

        if volume_exist:
            for idx, volume in enumerate(volumes):
                if is_envoy_based_proxy_agent() and volume['name'] == 'envoy-attachment-shared':
                    patches.append({
                       "op": "remove",
                       "path": f"/spec/volumes/{idx}"
                    })
                    app.logger.debug(f"Removed volume patch: {patches[-1]}")
                    break

    else:
        app.logger.debug("Before if: Sidecar 'open-appsec-nano-agent' does not exist. Preparing to add it.")

        sidecar = get_sidecar_container()

        volume_def = get_volume_definition()

        if is_envoy_based_proxy_agent():
            app.logger.debug(f"PROXY_KIND is {PROXY_KIND}, adding {PROXY_KIND}-specific components.")

            init_container = get_init_container(containers)

            volume_mount = get_volume_mount()

            if ENVOY_BASED_PROXY_CONTAINER_NAME:
                add_env_if_not_exist(containers, ENVOY_BASED_PROXY_CONTAINER_NAME, patches)
                add_env_variable_value_from(containers, ENVOY_BASED_PROXY_CONTAINER_NAME, 'OPENAPPSEC_UID', None, patches, value_from={"fieldRef": {"fieldPath": "metadata.uid"}})
                if LIBRARY_PATH_VALUE:
                    add_env_variable(containers, ENVOY_BASED_PROXY_CONTAINER_NAME, 'LD_LIBRARY_PATH', LIBRARY_PATH_VALUE, patches)
                if CONCURRENCY_CALC_VALUE:
                    add_env_variable(containers, ENVOY_BASED_PROXY_CONTAINER_NAME, 'CONCURRENCY_CALC', CONCURRENCY_CALC_VALUE, patches)
                if CONFIG_PORT_VALUE:
                    add_env_variable(containers, ENVOY_BASED_PROXY_CONTAINER_NAME, 'CONFIG_PORT', CONFIG_PORT_VALUE, patches)
                if CONCURRENCY_NUMBER_VALUE:
                    add_env_variable(containers, ENVOY_BASED_PROXY_CONTAINER_NAME, 'CONCURRENCY_NUMBER', CONCURRENCY_NUMBER_VALUE, patches)
            else:
                app.logger.debug("ENVOY_BASED_PROXY_CONTAINER_NAME skipping environment variable addition")

            patches.append({
                "op": "add",
                "path": "/spec/shareProcessNamespace",
                "value": True
            })
            app.logger.debug("Added shareProcessNamespace patch")

            patches.append({
                "op": "add",
                "path": "/spec/containers/0/volumeMounts/-",
                "value": volume_mount
            })
            app.logger.debug("Added volume mount patch to envoy-based-proxy: %s", patches[-1])

            if not init_container_exist:
                if 'initContainers' in obj['spec']:
                    obj['spec']['initContainers'].append(init_container)
                else:
                    obj['spec']['initContainers'] = [init_container]

                patches.append({
                    "op": "add",
                    "path": "/spec/initContainers",
                    "value": obj['spec']['initContainers']
                })

            if DEPLOY_FILTER:
                RELEASE_NAME = os.getenv('RELEASE_NAME', 'openappsec-waf-injected')
                if is_istio_agent() and SELECTOR_LABEL_NAME and SELECTOR_LABEL_VALUE:
                    envoy_filter_name = RELEASE_NAME + "-waf-filter"
                    create_or_update_envoy_filter(envoy_filter_name, namespace, SELECTOR_LABEL_NAME, SELECTOR_LABEL_VALUE)
                elif is_envoy_gateway_agent():
                    ensure_envoy_gateway_extension_apis()
                    policy_name = RELEASE_NAME + "-waf-patch-policy"
                    create_or_update_envoy_patch_policy(policy_name, GATEWAY_RESOURCE_NAME, GATEWAY_RESOURCE_NAMESPACE)
        else:
            app.logger.debug(f"PROXY_KIND is {PROXY_KIND}, skipping Istio-specific components.")

            current_spec = obj.get('spec', {})
            if 'automountServiceAccountToken' in current_spec:
                patches.append({
                    "op": "replace",
                    "path": "/spec/automountServiceAccountToken",
                    "value": True
                })
                app.logger.debug("Replaced existing automountServiceAccountToken=true for kong agent")
            else:
                patches.append({
                    "op": "add",
                    "path": "/spec/automountServiceAccountToken",
                    "value": True
                })
                app.logger.debug("Added automountServiceAccountToken=true for kong agent")

        if not sidecar_exists:
            patches.append({
                "op": "add",
                "path": "/spec/containers/-",
                "value": sidecar
            })
            app.logger.debug("Added sidecar container patch: %s", patches[-1])

            for volume in volume_def:
                patches.append({
                    "op": "add",
                    "path": "/spec/volumes/-",
                    "value": volume
                })
            app.logger.debug("Added volume definition patch: %s", patches[-1])
        else:
            app.logger.debug("Before else: Sidecar 'open-appsec-nano-agent' already exists. Checking for image updates.")

            for idx, container in enumerate(containers):
                if container['name'] == 'open-appsec-nano-agent':
                    current_image = container.get('image', '')
                    app.logger.debug("Current sidecar image: %s", current_image)
                    app.logger.debug("Desired sidecar image: %s", FULL_AGENT_IMAGE)
                    if current_image != FULL_AGENT_IMAGE:
                        patches.append({
                            "op": "replace",
                            "path": f"/spec/containers/{idx}/image",
                            "value": FULL_AGENT_IMAGE
                        })
                        app.logger.debug(f"Updated sidecar image patch: {patches[-1]}")
                    break

        if is_envoy_based_proxy_agent() and init_container_exist:
            app.logger.debug("Before else: init-container 'prepare-attachment' already exists. Checking for image updates.")

            for idx, container in enumerate(init_containers):
                if container['name'] == 'prepare-attachment':
                    current_image = container.get('image', '')
                    app.logger.debug("Current init container image: %s", current_image)
                    app.logger.debug("Desired init container image: %s", FULL_INIT_CONTAINER_IMAGE)
                    if current_image != FULL_INIT_CONTAINER_IMAGE:
                        patches.append({
                            "op": "replace",
                            "path": f"/spec/initContainers/{idx}/image",
                            "value": FULL_INIT_CONTAINER_IMAGE
                        })
                        app.logger.debug(f"Updated init container image patch: {patches[-1]}")
                    break


    app.logger.info("Total patches: %s", json.dumps(patches, indent=2))

    # Prepare the AdmissionReview response
    admission_response = {
        "kind": "AdmissionReview",
        "apiVersion": "admission.k8s.io/v1",
        "response": {
            "uid": uid,
            "allowed": True,
            "patchType": "JSONPatch",
            "patch": base64.b64encode(json.dumps(patches).encode('utf-8')).decode('utf-8')
        }
    }
    app.logger.debug("Sending admission response: %s", json.dumps(admission_response, indent=2))

    return jsonify(admission_response)

if __name__ == '__main__':
    # Configure logger
    configure_logging()

    # Ensure certificates exist
    secretgen.main()
    if not os.path.exists("/certs/server.crt") or not os.path.exists("/certs/server.key"):
        print("Error: Certificates not found. Exiting...")
        exit(1)

    cli = sys.modules['flask.cli']
    cli.show_server_banner = lambda *x: None

    # Run the Flask app with the generated certificates
    app.run(host='0.0.0.0', port=443, ssl_context=('/certs/server.crt', '/certs/server.key'))

