FROM ubuntu:22.04
LABEL org.opencontainers.image.authors="Ricerca Security <fuzzuf-dev@ricsec.co.jp>"

ARG SRC_DIR="/src"
ARG PIN_NAME="pin-3.7-97619-g0d0c92f4f-gcc-linux"
ARG PIN_URL="https://software.intel.com/sites/landingpage/pintool/downloads/${PIN_NAME}.tar.gz"
ARG PIN_PATH="${SRC_DIR}/${PIN_NAME}.tar.gz"
ARG NODE_VERSION="18"

# Install dependencies
RUN apt-get update \
  && apt-get -yq upgrade \
  && DEBIAN_FRONTEND=noninteractive apt-get install -yq ca-certificates curl gnupg \
  && mkdir -p /etc/apt/keyrings \
  && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
  && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_VERSION}.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list \
  && apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -yq \
    build-essential \
    cmake \
    git \
    pkg-config \
    python2.7-dev \
    python3 \
    python3-pip \
    doxygen \
    graphviz \
    mscgen \
    dia \
    wget \
    nodejs \
    afl++-clang \
    libfdt-dev \
    libglib2.0-dev \
    libpixman-1-dev \
    unzip \
    tar \
    zip \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

RUN git config --global --add safe.directory ${SRC_DIR}

# Install vcpkg
RUN mkdir -p ${SRC_DIR} \
  && git clone https://github.com/Microsoft/vcpkg.git ${SRC_DIR}/vcpkg \
  && cd ${SRC_DIR}/vcpkg \
  && ./bootstrap-vcpkg.sh -disableMetrics
ENV VCPKG_ROOT ${SRC_DIR}/vcpkg
ENV PATH ${SRC_DIR}/vcpkg:${PATH}

# Install fuzzuf/polytracker
RUN mkdir -p ${SRC_DIR} \
  && git clone https://github.com/fuzzuf/polytracker.git ${SRC_DIR}/polytracker \
  && cd ${SRC_DIR}/polytracker \
  && python3 -m pip install pytest \
  && python3 -m pip install -e .

# Download and extract Intel Pin
RUN mkdir -p ${SRC_DIR} \
  && cd ${SRC_DIR} \
  && wget ${PIN_URL} -O ${PIN_PATH} \
  && tar -xf ${PIN_PATH}
