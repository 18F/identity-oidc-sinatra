# Dockerfile

FROM ruby:3.3.4

WORKDIR /code
COPY . /code

RUN apt-get update && apt-get upgrade -y
RUN mkdir -p public/vendor
RUN cp .env.example .env
RUN bundle install
RUN npm install
RUN cp -R node_modules/@uswds/uswds/dist public/vendor/uswds


EXPOSE 9292

CMD ["bundle", "exec", "rackup", "--host", "0.0.0.0", "-p", "9292"]
