.PHONY: up down build migrate seed test test-cov cache-flush lint format shell logs \
        docker-clean locust-benchmark create-admin warm-cache setup init-env security test-fast \
        locust-headless

# ─── Docker ───────────────────────────────────────────────────────────────────

up:
	docker-compose up -d

down:
	docker-compose down --remove-orphans

build:
	docker-compose build --no-cache

logs:
	docker-compose logs -f api

docker-clean:
	docker-compose down -v --rmi local --remove-orphans

# ─── Database ─────────────────────────────────────────────────────────────────

migrate:
	docker-compose exec api python manage.py migrate --noinput

seed:
	docker-compose exec api python manage.py seed_data --users 3 --tasks-per-user 5

warm-cache:
	docker-compose exec api python manage.py warm_cache

# ─── Auth ─────────────────────────────────────────────────────────────────────

create-admin:
	docker-compose exec api python manage.py create_superuser_if_missing \
		--email admin@example.com \
		--password adminpass123

# ─── Testing ──────────────────────────────────────────────────────────────────

test:
	docker-compose exec api pytest -xvs --cov=apps --cov-report=term-missing

test-cov:
	docker-compose exec api pytest --cov=apps --cov-report=html

test-fast:
	docker-compose exec api pytest -x -q --no-header

# ─── Load Testing ─────────────────────────────────────────────────────────────

locust-benchmark:
	docker-compose exec api locust \
		-f tests/benchmarks/load_test.py \
		--host http://localhost:8000 \
		--web-host 0.0.0.0 \
		--web-port 8089

locust-headless:
	docker-compose exec api locust \
		-f tests/benchmarks/load_test.py \
		--headless -u 50 -r 5 --run-time 60s \
		--host http://localhost:8000 \
		--csv=tests/benchmarks/results

# ─── Code Quality ─────────────────────────────────────────────────────────────

lint:
	flake8 apps/ config/ tests/ --max-line-length=100 --exclude=migrations
	mypy apps/ --ignore-missing-imports

format:
	black apps/ config/ tests/
	isort apps/ config/ tests/

security:
	bandit -r apps/ -ll
	pip-audit -r requirements.txt

# ─── Dev Shortcuts ────────────────────────────────────────────────────────────

shell:
	docker-compose exec api python manage.py shell

cache-flush:
	docker-compose exec redis redis-cli FLUSHDB

# ─── Full Setup (first time) ──────────────────────────────────────────────────

init-env:
	@if [ ! -f .env ]; then cp .env.example .env; echo "📄 Created .env from .env.example"; else echo "📄 .env already exists"; fi

setup: init-env build up migrate seed create-admin warm-cache
	@echo "✅ Stack ready at http://localhost:8000"
	@echo "📚 Docs at http://localhost:8000/api/docs/"
	@echo "🔐 Admin at http://localhost:8000/admin/"
