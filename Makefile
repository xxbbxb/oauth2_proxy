.PHONY: build

clean:
	rm ./oauth2_proxy
	docker-compose down

default: build

build:
	@go build -a .

run: clean build
	./oauth2_proxy -provider=passport -config etc/oauth2_proxy.cfg

docker:
	docker-compose build

up: docker
	docker-compose up -d
