FROM ubuntu:latest

ENV DEBIAN_FRONTEND="noninteractive"

# Install basic dependencies
RUN apt-get -q -y update && \
  apt-get -q -y --no-install-recommends install autoconf automake \
  bash build-essential bzip2 ca-certificates curl dpkg-dev file \
  g++ gcc git-core imagemagick libbz2-dev libc6-dev libdb-dev libevent-dev \
  libffi-dev libgdbm-dev libglib2.0-dev libgmp-dev libjpeg-dev libkrb5-dev \
  liblzma-dev libmagickcore-dev libmagickwand-dev libmaxminddb-dev \
  libncurses-dev libncurses5-dev libncursesw5-dev libpng-dev libpq-dev \
  libreadline-dev libsctp-dev libsqlite3-dev libssl-dev libtool libwebp-dev \
  libxml2-dev libxslt-dev libyaml-dev locales make make mercurial patch python3 \
  unixodbc-dev unzip wget xz-utils zlib1g-dev zsh gnupg inotify-tools less \
  postgresql-client ssh direnv && apt-get -q -y clean

RUN locale-gen en_AU.UTF-8
ENV LANG en_AU.UTF-8
ENV LANGUAGE en_AU:en
ENV LC_ALL en_AU.UTF-8

ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID
RUN groupadd --gid ${USER_GID} ${USERNAME}
RUN useradd --shell /usr/bin/zsh --uid ${USER_UID} --gid ${USER_GID} -m ${USERNAME}
RUN mkdir /workspace && chown ${USERNAME}:${USERNAME} /workspace
RUN touch /entrypoint.sh && chown ${USERNAME}:${USERNAME} /entrypoint.sh
RUN mkdir -p /var/tmp/history && chown -R ${USERNAME}:${USERNAME} /var/tmp/history
RUN mkdir /storage && chown ${USERNAME}:${USERNAME} /storage

USER ${USERNAME}
ENV HOME=/home/${USERNAME}

WORKDIR $HOME

# Install oh-my-zsh
RUN sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

RUN echo '\neval "$(direnv hook zsh)"' >> ~/.zshrc

# Install ASDF
ARG ASDF_VERSION=0.10.2
RUN git clone https://github.com/asdf-vm/asdf.git ~/.asdf --branch v${ASDF_VERSION} && \
  echo '\nsource $HOME/.asdf/asdf.sh' >> ~/.bashrc && \
  echo '\nsource $HOME/.asdf/asdf.sh' >> ~/.zshrc

WORKDIR /workspace/
RUN mkdir _build deps .elixir_ls

# Install all the tools specified in the tool versions file.
COPY .tool-versions /workspace/
RUN /bin/bash -c 'source ~/.asdf/asdf.sh && \
  cat .tool-versions | cut -d \  -f 1 | xargs -n 1 asdf plugin add && \
  asdf install && \
  cat .tool-versions | xargs -n 2 asdf global'

# Elixir and Erlang setup (we just assume that Elixir was in the .tool-versions file)
ARG HEX_API_KEY
RUN /bin/bash -c 'source ~/.asdf/asdf.sh && \
  mix local.rebar --force && \
  mix local.hex --force'
ENV ERL_AFLAGS="-kernel shell_history enabled -kernel shell_history_path '\"/var/tmp/history/erlang.history\"'"

# Generate an entrypoint.sh
RUN echo '#!/bin/bash' > /entrypoint.sh && \
  echo 'source ~/.asdf/asdf.sh' >> /entrypoint.sh && \
  echo 'eval "$(direnv hook bash)"' >>  /entrypoint.sh && \
  echo 'exec "$@"' >> /entrypoint.sh && \
  chmod 755 /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]

# Prodigious use of asterisk to allow for files which may not exist.
COPY .env* .formatter.exs .tool-versions* bin* config* lib* priv* rel* test* CHANGELOG.md* mix.* /workspace/

RUN /bin/bash -c 'if [ -e .envrc ]; then /usr/bin/direnv allow; fi'

# Run mix deps.get
ARG GITHUB_TOKEN
RUN /bin/bash -c 'source ~/.asdf/asdf.sh && \
  mix deps.get && \
  (cd ash_auth_example ; mix deps.get)'

CMD ["zsh"]

