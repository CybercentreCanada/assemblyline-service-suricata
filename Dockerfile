FROM cccs/assemblyline-v4-service-base:latest AS base

ENV SERVICE_PATH suricata_.suricata_.Suricata
ENV SURICATA_VERSION 4.1.2

USER root

# Install APT dependancies
RUN apt-get update && apt-get install -y \
  git \
  libpcre3 \
  libpcap0.8 \
  libnet1 \
  libyaml-0-2 \
  zlib1g \
  libcap-ng0 \
  libjansson4 \
  liblua5.1-0 \
  libnss3 \
  liblz4-1 \
   && rm -rf /var/lib/apt/lists/*

FROM base AS build

# Install APT dependancies
RUN apt-get update && apt-get install -y \
  git \
  libpcre3 \
  libpcre3-dbg \
  libpcre3-dev \
  build-essential \
  autoconf \
  automake \
  libtool \
  libpcap-dev \
  libnet1-dev \
  libyaml-0-2 \
  libyaml-dev \
  zlib1g \
  zlib1g-dev \
  libcap-ng-dev \
  libcap-ng0 \
  make \
  libmagic-dev \
  libjansson-dev \
  libjansson4 \
  pkg-config \
  cargo \
  liblua5.1-0-dev \
  libnss3-dev \
  liblz4-dev \
  wget && rm -rf /var/lib/apt/lists/*

# Install PIP dependancies
USER assemblyline
RUN touch /tmp/before-pip
RUN pip install --user \
  gitpython \
  simplejson \
  python-dateutil \
  suricata-update \
  retrying && rm -rf ~/.cache/pip

USER root
RUN ln -s /var/lib/assemblyline/.local /root/.local

# Build suricata
RUN wget -O /tmp/suricata-${SURICATA_VERSION}.tar.gz https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz
RUN tar -xvzf /tmp/suricata-${SURICATA_VERSION}.tar.gz -C /tmp
WORKDIR /tmp/suricata-${SURICATA_VERSION}
RUN ./configure --disable-gccmarch-native --prefix=/build/ --sysconfdir=/etc/ --localstatedir=/var/ \
                --enable-python --enable-rust --enable-lua
RUN make -C /tmp/suricata-${SURICATA_VERSION}
RUN make -C /tmp/suricata-${SURICATA_VERSION} install
RUN ldconfig
RUN make -C /tmp/suricata-${SURICATA_VERSION} install-full

# Install suricata pip package
RUN pip install --user /tmp/suricata-${SURICATA_VERSION}/python

# Install stripe
COPY suricata_/stripe/* /tmp/stripe/
RUN /usr/bin/gcc -o /build/bin/stripe /tmp/stripe/stripe.c

# Remove files that existed before the pip install so that our copy command below doesn't take a snapshot of
# files that already exist in the base image
RUN find /var/lib/assemblyline/.local -type f ! -newer /tmp/before-pip -delete

# Switch back to root and change the ownership of the files to be copied due to bitbucket pipeline uid nonsense
RUN chown root:root -R /var/lib/assemblyline/.local

FROM base

# Get the updated local dir from builder
COPY --chown=assemblyline:assemblyline --from=build /var/lib/assemblyline/.local /var/lib/assemblyline/.local
COPY --from=build /build/ /usr/local/
COPY --from=build /etc/suricata/ /etc/suricata/
COPY --from=build /var/log/suricata/ /var/log/suricata/

# Create all suricata directories and set permissions
RUN mkdir -p /mount/updates && chown -R assemblyline /mount/updates
RUN mkdir -p /etc/suricata && chown -R assemblyline /etc/suricata
RUN mkdir -p /var/lib/suricata && chown -R assemblyline /var/lib/suricata
RUN mkdir -p /var/log/suricata && chown -R assemblyline /var/log/suricata
RUN mkdir -p /var/run/suricata && chown -R assemblyline /var/run/suricata

# Update suricata config
COPY suricata_/conf/suricata.yaml /etc/suricata/
RUN chown assemblyline /etc/suricata/suricata.yaml
RUN sed -i -e 's/__HOME_NET__/any/g' /etc/suricata/suricata.yaml
RUN sed -i -e 's/__RULE_FILES__/rule_files: []/g' /etc/suricata/suricata.yaml

# Update local rules using suricata-update script here
RUN touch /etc/suricata/suricata-rules-update
RUN chown -R assemblyline /var/lib/suricata/
RUN chown assemblyline /etc/suricata/suricata-rules-update

# Switch to assemblyline user
USER assemblyline

# Copy Suricata service code
WORKDIR /opt/al_service
COPY . .