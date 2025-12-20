.PHONY: clean
clean:
	sudo rm -rf data letsencrypt

.PHONY: zap
zap: stop clean start

.PHONY: start
start:
	docker compose up -d

.PHONY: stop
stop:
	docker compose down --remove-orphans --volumes
