# Multistage build using standalone Python builds with uv

# First, build the application in the `/app` directory
FROM ghcr.io/astral-sh/uv:bookworm-slim AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

# Configure the Python directory so it is consistent
ENV UV_PYTHON_INSTALL_DIR=/python

# Only use the managed Python version
ENV UV_PYTHON_PREFERENCE=only-managed

# Install Python before the project for caching
RUN uv python install 3.12

WORKDIR /app

# Copy pyproject.toml and install dependencies
COPY pyproject.toml .
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync

# Copy executor code and config
COPY config.py .
COPY executor_service.py .

# Final image without uv
FROM debian:bookworm-slim

# Setup a non-root user
RUN groupadd --system --gid 999 executor \
    && useradd --system --gid 999 --uid 999 --create-home executor

# Copy the Python version
COPY --from=builder --chown=executor:executor /python /python

# Copy the application from the builder
COPY --from=builder --chown=executor:executor /app /app

# Place executables in the environment at the front of the path
ENV PATH="/app/.venv/bin:$PATH"

# Use the non-root user
USER executor

WORKDIR /app

EXPOSE 4323

CMD ["python", "executor_service.py"]