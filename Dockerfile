FROM sfoxdev/softether-client:latest

RUN apk update ; apk add gcc make libc-dev git screen ; \
	git clone https://github.com/agkr234/qwfwd ; \
	cd /qwfwd/ ; \
	./configure ; \
	make ; \
	mkdir bin ; cp qwfwd.bin qwfwd.cfg bin ; \
	make clean
RUN apk add python3 curl bash ; curl -kL https://bootstrap.pypa.io/get-pip.py | python3 ; \
	pip install ping3==3.0.2 mysql-connector-python==8.0.27 beautifulsoup4==4.10.0 ptvsd==4.3.2

RUN mkdir -p /app

ADD sevpn.py /app
ADD main_container.py /app
ADD start.sh /app
ADD reset.py /app
ADD sevpn.ini /app

RUN chmod -R 777 /app

ADD qwfwd_start.sh /qwfwd/bin

RUN chmod -R 777 /qwfwd/bin

EXPOSE 30000/udp

WORKDIR /app
ENTRYPOINT ["python3"]