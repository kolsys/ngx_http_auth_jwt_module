ARG NGINX_VERSION=1.17.8
FROM nginx:$NGINX_VERSION-alpine


RUN apk add --no-cache cmake make gcc libc-dev g++ openssl-dev pcre-dev zlib-dev
RUN wget https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz \
		&& tar -zxf nginx-$NGINX_VERSION.tar.gz \
	&& wget https://github.com/akheron/jansson/archive/v2.12.tar.gz \
		&& tar -zxf v2.12.tar.gz \
	&& wget https://github.com/benmcollins/libjwt/archive/v1.12.0.tar.gz \
		&& tar -zxf v1.12.0.tar.gz \
	&& cd ../jansson-2.12 && cmake . && make install && cd .. \
	&& cd libjwt-1.12.0 && cmake -D BUILD_SHARED_LIBS=1 . && make install && cd ..
	# && wget https://github.com/tizpuppi/ngx_http_auth_jwt_module/archive/0.0.1.tar.gz \
		# && tar -zxf 0.0.1.tar.gz && mv ngx_http_auth_jwt_module-0.0.1 ngx_http_auth_jwt_module\

RUN rm -rf ngx_http_auth_jwt_module
COPY ./* ngx_http_auth_jwt_module/

RUN cd nginx-$NGINX_VERSION \
	&& ./configure --with-compat --add-dynamic-module=../ngx_http_auth_jwt_module \
	&& make modules

FROM nginx:$NGINX_VERSION
COPY --from=0 nginx-$NGINX_VERSION/objs/ngx_http_auth_jwt_module.so /etc/nginx/modules/
COPY --from=0 /lib/libc.musl-x86_64.so.1 /lib/libc.musl-x86_64.so.1
COPY --from=0 /usr/local/lib/libjwt.so /usr/lib/libjwt.so
RUN sed -i '1s!^!load_module modules/ngx_http_auth_jwt_module.so;!' /etc/nginx/nginx.conf
