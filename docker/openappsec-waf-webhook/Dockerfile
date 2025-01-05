# Use Python 3.9 slim image as the base
FROM python:3.9-slim

# Install dependencies
RUN pip install kubernetes cryptography flask --progress-bar off

# Create directory for certs
RUN mkdir -p /certs

# Copy the Python scripts
COPY keygen.py /app/keygen.py
COPY webhook_server.py /app/webhook_server.py
COPY secretgen.py /app/secretgen.py
COPY run.sh /app/run.sh

# Make the script executable
RUN chmod +x /app/run.sh

# Set the working directory
WORKDIR /app

# Expose port 443
EXPOSE 443

# Run the webhook server
CMD ["/app/run.sh"]