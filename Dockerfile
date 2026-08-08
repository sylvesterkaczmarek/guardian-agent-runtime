FROM python:3.12-slim
WORKDIR /work
COPY requirements.lock pyproject.toml ./
RUN python -m pip install --no-cache-dir --no-deps -r requirements.lock
COPY . /work
RUN python -m pip install --no-cache-dir --no-deps --no-build-isolation -e .
RUN python -m pip check
CMD ["make", "test"]
