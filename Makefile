.PHONY: up down build migrate test test-cov cache-flush lint format shell logs docker-clean

up:
	docker-compose up -d

down:
	docker-compose down --remove-orphans

build:
	docker-compose build --no-cache

migrate:
	docker-compose exec api python manage.py migrate --noinput

test:
	docker-compose exec api pytest -xvs --cov=apps --cov-report=term-missing

test-cov:
	docker-compose exec api pytest --cov=apps --cov-report=html

cache-flush:
	docker-compose exec redis redis-cli FLUSHDB

lint:
	flake8 apps/ && mypy apps/

format:
	black apps/ && isort apps/

shell:
	docker-compose exec api python manage.py shell

logs:
	docker-compose logs -f api

docker-clean:
	docker-compose down -v --rmi local --remove-orphans