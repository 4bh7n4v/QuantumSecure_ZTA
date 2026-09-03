.PHONY: build up down restart logs clean

build:
	docker compose build

up:
	sudo service docker start
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f

clean:
	docker compose down --rmi all --volumes --remove-orphans

gateway:
	docker build -f ./docker/gateway/Dockerfile -t sdp-gateway .

client:
	docker build -f ./docker/client/Dockerfile -t sdp-client .

resource:
	docker build -f ./docker/resource/Dockerfile -t resource-node .
