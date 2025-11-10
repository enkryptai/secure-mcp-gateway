# OAuth Callback Relay Service
# Minimal, secure container for hosting centralized OAuth callback

FROM python:3.11-slim

# Security: Run as non-root user
RUN useradd -m -u 1000 relay && \
    mkdir -p /app && \
    chown -R relay:relay /app

WORKDIR /app

# Copy requirements and install dependencies
COPY --chown=relay:relay requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY --chown=relay:relay app.py .
COPY --chown=relay:relay static/ static/

# Switch to non-root user
USER relay

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health').read()"

# Run with Gunicorn (production WSGI server)
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "4", "--timeout", "30", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
