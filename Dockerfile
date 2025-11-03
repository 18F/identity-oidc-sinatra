# Dockerfile

FROM ruby:3.4.4

WORKDIR /code
COPY . /code

ENV BUNDLER_VERSION="2.6.9"
ENV NODE_MAJOR 22

RUN mkdir -p public/vendor
RUN cp .env.example .env

RUN gem install bundler --version $BUNDLER_VERSION
RUN sh -c 'bundle check || bundle install --deployment --jobs=4 --retry=3 --without deploy development doc production --path vendor/bundle'

RUN mkdir -p /etc/apt/keyrings
RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
RUN echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_$NODE_MAJOR.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list

RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list

RUN apt-get update -qq && apt-get upgrade -y
RUN apt-get install -y --no-install-recommends nodejs \
      locales

RUN npm install
RUN cp -R node_modules/@uswds/uswds/dist public/vendor/uswds

EXPOSE 9292

CMD ["bundle", "exec", "rackup", "--host", "0.0.0.0", "-p", "9292"]
