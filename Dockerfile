FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_VERSION=0.13.6 \
    UV_NO_CACHE=1 \
    PATH="/app/.venv/bin:${PATH}"

WORKDIR /app

# Install the locked runtime and HTTP server dependencies without copying user config.
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir "uv==${UV_VERSION}" \
    && uv sync --frozen --no-dev --extra server

RUN useradd --create-home --shell /usr/sbin/nologin subio

USER subio

EXPOSE 8000

ENTRYPOINT ["subio"]
CMD ["serve", "/config/config.toml", "--host", "0.0.0.0", "--port", "8000"]
