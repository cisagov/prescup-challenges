FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy the app code
COPY ./app /app

# Set these arguments as environment variables.
ENV token1=${token1}
ENV token2=${token2}
ENV token3=${token3}
ENV token4=${token4}
ENV token5=${token5}
ENV token6=${token6}

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Expose the Flask port
EXPOSE 5000

# Start the web dashboard
RUN chmod +x start.sh
CMD ["./start.sh"]
