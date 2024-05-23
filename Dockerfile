FROM python:3.9 AS build

WORKDIR /app
COPY requirements.txt requirements.txt
COPY cs_scanimage.py /app/cs_imagescan.py

RUN pip install --user -r requirements.txt

ENTRYPOINT ["python", "cs_imagescan.py"]

FROM gcr.io/distroless/python3-debian11:latest

COPY --from=build /root/.local /root/.local
COPY --from=build /app /app

ENV PATH="/opt/venv/bin:$PATH"

ENTRYPOINT [ "python", "/app/cs_imagescan.py" ]
