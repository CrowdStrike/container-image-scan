FROM python:3.9 AS base

WORKDIR /app
COPY cs_scanimage.py /app/cs_imagescan.py

RUN pip install --user docker crowdstrike-falconpy

ENTRYPOINT ["python", "cs_imagescan.py"]

FROM gcr.io/distroless/python3-debian11:latest AS final

COPY --from=base /root/.local /root/.local
COPY --from=base /app /app

ENV PATH="/opt/venv/bin:$PATH"

ENTRYPOINT [ "python", "/app/cs_imagescan.py" ]