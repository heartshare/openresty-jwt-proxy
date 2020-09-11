FROM openresty/openresty:alpine-fat

RUN apk --no-cache add --virtual .run-deps ca-certificates curl

RUN rm /usr/local/openresty/nginx/conf/nginx.conf

ADD files/nginx-jwt.tar.gz /usr/local/openresty/

COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
