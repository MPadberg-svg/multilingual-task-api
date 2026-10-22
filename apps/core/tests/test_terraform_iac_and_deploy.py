from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
TERRAFORM_DIR = REPO_ROOT / "terraform"
DEPLOY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "deploy.yml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
DOCKER_COMPOSE = REPO_ROOT / "docker-compose.yml"
MAKEFILE = REPO_ROOT / "Makefile"


def test_cloudfront_forwards_all_auth_tenant_idempotency_and_trace_headers():
    """
    CloudFront strips non-allowlisted headers before forwarding to the ALB origin.
    Every custom request header consumed by Django middleware / DRF authentication
    must be explicitly forwarded with zero edge TTL to prevent stripped headers or
    cross-tenant response caching.
    """
    main_tf = (TERRAFORM_DIR / "main.tf").read_text(encoding="utf-8")
    cdn_block = main_tf.split('resource "aws_cloudfront_distribution" "cdn"', 1)[1]

    required_headers = [
        "Accept-Language",
        "Authorization",
        "Idempotency-Key",
        "Origin",
        "X-API-Key",
        "X-Correlation-Id",
        "X-Organization-ID",
        "traceparent",
    ]
    for header in required_headers:
        assert f'"{header}"' in cdn_block, f"CloudFront missing forwarded header: {header}"

    assert "default_ttl            = 0" in cdn_block
    assert "max_ttl                = 0" in cdn_block
    assert 'viewer_protocol_policy = "redirect-to-https"' in cdn_block


def test_github_oidc_role_enforces_repo_subject_and_scoped_passrole():
    """
    GitHub OIDC federation must restrict AssumeRoleWithWebIdentity to this repository
    and restrict iam:PassRole strictly to the two ECS task roles with PassedToService.
    """
    main_tf = (TERRAFORM_DIR / "main.tf").read_text(encoding="utf-8")
    variables_tf = (TERRAFORM_DIR / "variables.tf").read_text(encoding="utf-8")

    assert 'resource "aws_iam_openid_connect_provider" "github"' in main_tf
    assert "https://token.actions.githubusercontent.com" in main_tf
    assert '"token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"' in main_tf
    assert (
        '"token.actions.githubusercontent.com:sub" = "repo:${var.github_repository}:*"' in main_tf
    )
    assert 'default     = "MPadberg-svg/multilingual-task-api"' in variables_tf

    policy_block = main_tf.split('resource "aws_iam_role_policy" "github_actions_deploy"', 1)[1]
    pass_role_block = policy_block.split('Sid    = "PassOnlyECSTaskRoles"', 1)[1].split(
        '\nresource "', 1
    )[0]
    assert "aws_iam_role.ecs_task_execution.arn" in pass_role_block
    assert "aws_iam_role.ecs_task.arn" in pass_role_block
    assert '"iam:PassedToService" = "ecs-tasks.amazonaws.com"' in pass_role_block
    assert 'Resource = "*"' not in pass_role_block


def test_celery_beat_singleton_ecs_service_and_docker_compose_parity():
    """
    Celery Beat must run as a singleton (desired_count=1, min=0%, max=100%) in ECS
    using the exact same config.celery + DatabaseScheduler command as docker-compose.yml.
    """
    main_tf = (TERRAFORM_DIR / "main.tf").read_text(encoding="utf-8")
    compose = yaml.safe_load(DOCKER_COMPOSE.read_text(encoding="utf-8"))

    compose_beat_cmd = compose["services"]["celery-beat"]["command"]
    assert "celery -A config.celery beat" in compose_beat_cmd
    assert "django_celery_beat.schedulers:DatabaseScheduler" in compose_beat_cmd

    beat_task_block = main_tf.split('resource "aws_ecs_task_definition" "celery_beat"', 1)[1].split(
        'resource "aws_ecs_cluster" "main"', 1
    )[0]
    assert '"celery", "-A", "config.celery", "beat"' in beat_task_block
    assert '"django_celery_beat.schedulers:DatabaseScheduler"' in beat_task_block

    beat_svc_block = main_tf.split('resource "aws_ecs_service" "celery_beat"', 1)[1].split(
        'resource "aws_appautoscaling_target" "ecs"', 1
    )[0]
    assert "desired_count                      = 1" in beat_svc_block
    assert "deployment_minimum_healthy_percent = 0" in beat_svc_block
    assert "deployment_maximum_percent         = 100" in beat_svc_block


def test_deploy_workflow_registers_new_image_before_migrations_and_matches_outputs():
    """
    Verify deploy.yml:
    1. Grants id-token: write for AWS OIDC authentication.
    2. Registers the new API task definition revision BEFORE running `manage.py migrate`
       so newly added migrations in commit N execute prior to updating live ECS pods.
    3. Has 1-to-1 Terraform output and Makefile sync-github-vars bindings.
    """
    deploy = yaml.safe_load(DEPLOY_WORKFLOW.read_text(encoding="utf-8"))
    outputs_tf = (TERRAFORM_DIR / "outputs.tf").read_text(encoding="utf-8")
    makefile_text = MAKEFILE.read_text(encoding="utf-8")

    assert deploy["permissions"]["id-token"] == "write"

    deploy_steps = deploy["jobs"]["deploy"]["steps"]
    step_names = [s.get("name", "") for s in deploy_steps]
    reg_idx = step_names.index("Register updated API task definition revision")
    mig_idx = step_names.index("Run database migrations synchronously before rollout")
    rollout_idx = step_names.index("Deploy ECS API service (rolling update)")
    assert reg_idx < mig_idx < rollout_idx

    migration_script = deploy_steps[mig_idx]["run"]
    assert '"$NEW_API_TASK_DEF_ARN"' in migration_script

    expected_terraform_outputs = [
        "ecr_repository_url",
        "github_actions_role_arn",
        "ecs_cluster_name",
        "ecs_api_service_name",
        "ecs_celery_service_name",
        "ecs_celery_beat_service_name",
        "ecs_api_task_family",
        "ecs_celery_task_family",
        "ecs_celery_beat_task_family",
        "private_subnet_ids",
        "ecs_security_group_id",
    ]
    for output_name in expected_terraform_outputs:
        assert f'output "{output_name}"' in outputs_tf
        assert output_name in makefile_text

    expected_gh_vars = [
        "AWS_REGION",
        "AWS_ROLE_ARN",
        "ECR_REPOSITORY",
        "ECS_CLUSTER",
        "ECS_SERVICE",
        "ECS_TASK_DEFINITION",
        "ECS_CELERY_SERVICE",
        "ECS_CELERY_TASK_DEFINITION",
        "ECS_CELERY_BEAT_SERVICE",
        "ECS_CELERY_BEAT_TASK_DEFINITION",
        "PRIVATE_SUBNET_IDS",
        "ECS_SECURITY_GROUP_ID",
    ]
    for gh_var in expected_gh_vars:
        assert f"gh variable set {gh_var}" in makefile_text


def test_ci_workflow_enforces_terraform_fmt_and_validate():
    ci = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    tf_job = ci["jobs"]["terraform"]
    joined_runs = "\n".join(step.get("run", "") for step in tf_job["steps"])
    assert "terraform fmt -check -recursive terraform/" in joined_runs
    assert "terraform init -backend=false" in joined_runs
    assert "terraform validate" in joined_runs
