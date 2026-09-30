FROM alpine:3.23.6@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0
RUN apk add --no-cache apk-tools=3.0.8-r0 python3 openssl nodejs
COPY packaging/ /packaging/
COPY zerotier-ui/ /zerotier-ui/
ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /zerotier-ui
RUN timeout 60s node --test test_ui.cjs && timeout 60s python3 -B -m unittest discover -s . -p 'test_package.py'
ENTRYPOINT ["python3", "/zerotier-ui/build.py"]
