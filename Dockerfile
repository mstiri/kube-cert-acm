FROM python:3.9.7-alpine3.14
RUN addgroup -S appgrp && adduser -S appusr -G appgrp -h /app
WORKDIR /app
COPY requirements.txt main.py helpers.py logger.py ./
RUN apk upgrade && apk add --no-cache  --virtual .build-deps gcc musl-dev python3-dev libffi-dev && \
  pip3 install  --no-cache-dir -r requirements.txt && \
  apk del .build-deps python3-dev libffi-dev
USER appusr
CMD ["python3", "-m", "main"]
