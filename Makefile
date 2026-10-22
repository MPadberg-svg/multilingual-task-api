.PHONY: up down build migrate seed test test-cov test-local cache-flush lint format shell logs \
        docker-clean locust-benchmark create-admin warm-cache setup security test-fast \
        locust-headless tf-fmt tf-validate sync-github-vars

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

# Run tests locally without Docker (uses SQLite via config.settings.testing)
test-local:
	pytest -x -q --no-header

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
	black --check --line-length=100 apps/ config/ tests/
	isort --check-only apps/ config/ tests/
	mypy apps/ config/

format:
	black --line-length=100 apps/ config/ tests/
	isort apps/ config/ tests/

security:
	bandit -r apps/ config/ -ll --exclude apps/core/migrations,apps/tasks/migrations
	pip-audit -r requirements.txt --strict

# ─── Dev Shortcuts ────────────────────────────────────────────────────────────

shell:
	docker-compose exec api python manage.py shell

cache-flush:
	docker-compose exec redis redis-cli FLUSHDB

# ─── Full Setup (first time) ──────────────────────────────────────────────────

setup: build up migrate seed create-admin warm-cache
	@echo "✅ Stack ready at http://localhost:8000"
	@echo "📚 Docs at http://localhost:8000/api/docs/"
	@echo "🔐 Admin at http://localhost:8000/admin/"

# ─── Infrastructure & Cloud Rollout ───────────────────────────────────────────

tf-fmt:
	terraform fmt -check -recursive terraform/

tf-validate:
	terraform -chdir=terraform init -backend=false
	terraform -chdir=terraform validate

sync-github-vars:
	@OUT=$$(terraform -chdir=terraform output -json); \
	gh variable set AWS_REGION --body "$${AWS_REGION:-us-east-1}"; \
	gh variable set AWS_ROLE_ARN --body "$$(echo "$$OUT" | jq -r '.github_actions_role_arn.value')"; \
	gh variable set ECR_REPOSITORY --body "$$(echo "$$OUT" | jq -r '.ecr_repository_url.value')"; \
	gh variable set ECS_CLUSTER --body "$$(echo "$$OUT" | jq -r '.ecs_cluster_name.value')"; \
	gh variable set ECS_SERVICE --body "$$(echo "$$OUT" | jq -r '.ecs_api_service_name.value')"; \
	gh variable set ECS_TASK_DEFINITION --body "$$(echo "$$OUT" | jq -r '.ecs_api_task_family.value')"; \
	gh variable set ECS_CELERY_SERVICE --body "$$(echo "$$OUT" | jq -r '.ecs_celery_service_name.value')"; \
	gh variable set ECS_CELERY_TASK_DEFINITION --body "$$(echo "$$OUT" | jq -r '.ecs_celery_task_family.value')"; \
	gh variable set ECS_CELERY_BEAT_SERVICE --body "$$(echo "$$OUT" | jq -r '.ecs_celery_beat_service_name.value')"; \
	gh variable set ECS_CELERY_BEAT_TASK_DEFINITION --body "$$(echo "$$OUT" | jq -r '.ecs_celery_beat_task_family.value')"; \
	gh variable set CLOUDFRONT_DOMAIN --body "$$(echo "$$OUT" | jq -r '.cloudfront_domain.value')"; \
	gh variable set PRIVATE_SUBNET_IDS --body "$$(echo "$$OUT" | jq -r '.private_subnet_ids.value | map("\"" + . + "\"") | join(",")')"; \
	gh variable set ECS_SECURITY_GROUP_ID --body "$$(echo "$$OUT" | jq -r '.ecs_security_group_id.value')"

