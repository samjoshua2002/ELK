# Stage 1: Build C++ Agent
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libcurl4-openssl-dev \
    curl

# Create app directory
WORKDIR /app

# Copy CMakeLists and source
COPY CMakeLists.txt .
COPY src src
COPY include include

# Build
RUN mkdir build && cd build && cmake .. && make

# Stage 2: Runtime Environment
FROM ubuntu:22.04

# Install libcurl runtime
RUN apt-get update && apt-get install -y libcurl4 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/build/siem_agent .

# Default command to run the agent
CMD ["./siem_agent"]
