# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Set the working directory in the container
WORKDIR /Authorization-authentication

# Copy the current directory contents into the container at /app
COPY . /Authorization-authentication

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 80 available to the world outside this container
EXPOSE 6000

# Run app.py when the container launches
CMD ["python", "auth.py"]
