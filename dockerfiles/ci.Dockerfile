FROM public.ecr.aws/docker/library/ruby:3.3.4-bullseye

RUN curl -sL https://deb.nodesource.com/setup_18.x | bash -

RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list

RUN curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add - \
    && echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list

RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list


RUN apt-get update -qq
RUN apt-get install -y --no-install-recommends nodejs \
      locales \
      yarn
RUN  curl -L -o cf8-cli_linux_x86-64.tgz "https://packages.cloudfoundry.org/stable?release=linux64-binary&version=v8&source=github" && \
      tar -xvzf cf8-cli_linux_x86-64.tgz && \
      mv cf8 /usr/local/bin && \
      cf8 --version
 
RUN find / -perm /6000 -type f -exec chmod a-s {} \; || true

