ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch AS base

ENV SERVICE_PATH suricata_.suricata_.Suricata

USER root

# Install APT dependancies for both build and final image
RUN apt-get update && apt-get install --no-install-recommends -y libjansson-dev libpcap-dev libyaml-dev \
    wireshark-common \
    && rm -rf /var/lib/apt/lists/*

FROM base AS build
# Install APT dependancies for compilation
RUN apt-get update && apt-get install --no-install-recommends -y curl autoconf automake build-essential \
    cbindgen libpcre2-dev libtool make pkg-config zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Install PIP dependancies
USER assemblyline
COPY requirements.txt /tmp/requirements.txt
RUN touch /tmp/before-pip && pip install --no-cache-dir --user -r /tmp/requirements.txt && rm -rf ~/.cache/pip

# Install rustup
USER root
RUN ln -s /var/lib/assemblyline/.local /root/.local && curl https://sh.rustup.rs -sSf | sh -s -- -y
SHELL ["bash", "-lc"]
RUN export PATH=$PATH:${HOME}/.cargo/bin && cargo install --force cbindgen

# Build suricata
RUN mkdir -p /suricata
WORKDIR /suricata
ADD https://github.com/OISF/suricata.git#main-8.0.x /suricata/suricata
WORKDIR /suricata/suricata
RUN ./scripts/bundle.sh && ./autogen.sh &&./configure --disable-gccmarch-native && make && \
    DESTDIR=/suricata/suricata/fakeroot make install install-conf && \
    ldconfig

# Install stripe
COPY suricata_/stripe/* /tmp/stripe/
RUN mkdir -p /build/bin && /usr/bin/gcc -o /build/bin/stripe /tmp/stripe/stripe.c

# Remove files that existed before the pip install so that our copy command below doesn't take a snapshot of
# files that already exist in the base image
RUN find /var/lib/assemblyline/.local -type f ! -newer /tmp/before-pip -delete

# Switch back to root and change the ownership of the files
RUN chown root:root -R /var/lib/assemblyline/.local

FROM base
# Get the updated local dir from builder
COPY --chown=assemblyline:assemblyline --from=build /var/lib/assemblyline/.local /var/lib/assemblyline/.local
COPY --from=build /suricata/suricata/fakeroot /
COPY --from=build /build/bin/stripe /usr/local/bin/stripe
RUN ldconfig

ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PYTHONPATH="/usr/local/lib/suricata/python:$PYTHONPATH"

# Create all suricata directories and set permissions
RUN mkdir -p /mount/updates && chown -R assemblyline /mount/updates
# Update suricata config
COPY suricata_/conf/suricata.yaml /usr/local/etc/suricata/
RUN sed -i -e 's/__HOME_NET__/any/g' /usr/local/etc/suricata/suricata.yaml && \
    sed -i -e 's/\/var\/run\/suricata/\/usr\/local\/var\/run\/suricata\//g' /usr/local/etc/suricata/suricata.yaml && \
    sed -i -e 's/\/etc\/suricata\//\/usr\/local\/etc\/suricata\//g' /usr/local/etc/suricata/suricata.yaml && \
    sed -i -e 's/\/var\/log\/suricata\//\/usr\/local\/var\/log\/suricata\//g' /usr/local/etc/suricata/suricata.yaml && \
    sed -i -e 's/__RULE_FILES__/rule-files: []/g' /usr/local/etc/suricata/suricata.yaml && \
    touch /usr/local/etc/suricata/suricata-rules-update

# Change ownership of suricata directories to be accesible by assemblyline user
RUN chown -R assemblyline \
    /usr/local/etc/suricata \
    /usr/local/var/lib/suricata \
    /usr/local/var/log/suricata \
    /usr/local/var/run/suricata \
    /usr/local/etc/suricata/suricata-rules-update

# Switch to assemblyline user
USER assemblyline

# Copy Suricata service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
