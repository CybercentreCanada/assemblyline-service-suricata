ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch AS base

ENV SERVICE_PATH suricata_.suricata_.Suricata
ENV SURICATA_VERSION 0.8-dev
ENV SURICATA_COMMIT a10c1f1dded570f99c4972ef9f730cec79218b75

USER root

# Install APT dependancies
RUN apt-get update && apt-get install -y wget curl\
  libpcre3 libpcre3-dbg libpcre3-dev build-essential libpcap-dev   \
  libnet1-dev libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev \
  libcap-ng-dev libcap-ng0 make libmagic-dev libjansson-dev\
  libnss3-dev libgeoip-dev liblua5.1-dev libhiredis-dev libevent-dev \
  rustc cargo autoconf libpcre2-dev\
  libtool jq git-core automake liblz4-dev\
  && rm -rf /var/lib/apt/lists/*

FROM base AS build

# Install PIP dependancies
USER assemblyline
RUN touch /tmp/before-pip
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --user -r /tmp/requirements.txt && rm -rf ~/.cache/pip

# Installing cargo as assemblyline user

# Install rustup (purge rustc)
USER root
RUN ln -s /var/lib/assemblyline/.local /root/.local
RUN apt remove --purge -y rustc
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
SHELL ["bash", "-lc"]
RUN export PATH=$PATH:${HOME}/.cargo/bin
RUN cargo install --force cbindgen


# Build suricata
RUN mkdir -p /suricata
WORKDIR /suricata
RUN git clone https://github.com/OISF/suricata.git
WORKDIR /suricata/suricata
RUN git checkout ${SURICATA_COMMIT}
RUN ./scripts/bundle.sh
RUN ./autogen.sh
RUN ./configure --disable-gccmarch-native
RUN make
RUN DESTDIR=/suricata/suricata/fakeroot make install install-conf
RUN ldconfig

# Install stripe
COPY suricata_/stripe/* /tmp/stripe/
RUN mkdir -p /build/bin
RUN /usr/bin/gcc -o /build/bin/stripe /tmp/stripe/stripe.c

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
# # # Create all suricata directories and set permissions
RUN mkdir -p /mount/updates && chown -R assemblyline /mount/updates

# Update suricata config
COPY suricata_/conf/suricata.yaml /usr/local/etc/suricata/
RUN sed -i -e 's/__HOME_NET__/any/g' /usr/local/etc/suricata/suricata.yaml
RUN sed -i -e 's/\/var\/run\/suricata/\/usr\/local\/var\/run\/suricata\//g' /usr/local/etc/suricata/suricata.yaml
RUN sed -i -e 's/\/etc\/suricata\//\/usr\/local\/etc\/suricata\//g' /usr/local/etc/suricata/suricata.yaml
RUN sed -i -e 's/\/var\/log\/suricata\//\/usr\/local\/var\/log\/suricata\//g' /usr/local/etc/suricata/suricata.yaml
RUN sed -i -e 's/__RULE_FILES__/rule-files: []/g' /usr/local/etc/suricata/suricata.yaml

RUN touch /usr/local/etc/suricata/suricata-rules-update

RUN chown -R assemblyline /usr/local/etc/suricata
RUN chown -R assemblyline /usr/local/var/lib/suricata
RUN chown -R assemblyline /usr/local/var/log/suricata
RUN chown -R assemblyline /usr/local/var/run/suricata
RUN chown assemblyline /usr/local/etc/suricata/suricata-rules-update

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
