# SIEM Project: Operations Guide

This guide provides instructions on how to start and stop the entire SIEM (System Information and Event Management) stack, including the Elasticsearch/Kibana backend and the C++ Log Agent.

---

## 🚀 How to Start Everything

### Option A: Fully Dockerized (Recommended)
This method runs everything—Elasticsearch, Kibana, and the C++ Agent—inside Docker containers.

1. **Navigate to the docker directory:**
   ```bash
   cd docker
   ```
2. **Start the stack:**
   ```bash
   docker-compose up -d --build
   ```
   *Note: Using `--build` ensures any changes to the C++ agent source are re-compiled into the container.*

### Option B: Development Mode (Local Agent)
If you are developing the C++ agent and want to run it on your host machine while using Docker for the database:

1. **Start the Backend (ELK):**
   ```bash
   cd docker
   # We only start the database and dashboard
   docker-compose up -d elasticsearch kibana
   ```
2. **Build the C++ Agent locally:**
   ```bash
   cd ../agent
   mkdir -p build && cd build
   cmake ..
   make
   ```
3. **Run the Agent:**
   ```bash
   # Point it to your local log file
   ./siem_agent ../../logs/test_auth.log
   ```

---

## 🛑 How to Stop Everything

### If using Docker (Option A):
1. **Navigate to the docker directory:**
   ```bash
   cd docker
   ```
2. **Shut down the containers:**
   ```bash
   docker-compose down
   ```
   *Note: This stops and removes the containers but keeps the data in the `es_data` volume.*

### If running locally (Option B):
1. **Stop the C++ Agent:**
   Press `Ctrl + C` in the terminal where the agent is running.
2. **Stop the Backend:**
   ```bash
   cd docker
   docker-compose down
   ```

---

## 🧪 Quick Test Commands
Once everything is started, you can simulate a security event by adding a line to the log file:

```bash
echo "Mar  9 00:00:01 node-1 sshd[1234]: Failed password for invalid user hacker from 10.0.0.50 port 3333 ssh2" >> logs/test_auth.log
```

You can then verify the alert in **Kibana** at [http://localhost:5601](http://localhost:5601).
