from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
TERRAFORM_DIR = REPO_ROOT / "terraform"
DOCKERFILE = REPO_ROOT / "Dockerfile"
DOCKERIGNORE = REPO_ROOT / ".dockerignore"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
DEPLOY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "deploy.yml"


def test_cloudfront_wafv2_enforces_us_east_1_rate_limit_and_rlhf_body_override():
    """
    CloudFront WAFv2 WebACLs must use an explicit us-east-1 provider alias, enforce
    per-IP rate limiting + AWS IP reputation + CommonRuleSet, and override
    SizeRestrictions_BODY to count so >8 KB RLHF prompts and /tasks/bulk/ batches
    are not false-positively blocked at the CDN edge.
    """
    main_tf = (TERRAFORM_DIR / "main.tf").read_text(encoding="utf-8")
    outputs_tf = (TERRAFORM_DIR / "outputs.tf").read_text(encoding="utf-8")

    assert 'alias  = "us_east_1"' in main_tf
    assert 'region = "us-east-1"' in main_tf

    waf_block = main_tf.split('resource "aws_wafv2_web_acl" "cdn"', 1)[1].split('\nresource "', 1)[
        0
    ]
    assert "provider    = aws.us_east_1" in waf_block
    assert 'scope       = "CLOUDFRONT"' in waf_block
    assert 'name     = "RateLimitPerIP"' in waf_block
    assert 'name        = "AWSManagedRulesAmazonIpReputationList"' in waf_block
    assert 'name        = "AWSManagedRulesCommonRuleSet"' in waf_block
    assert 'name = "SizeRestrictions_BODY"' in waf_block
    assert "count {}" in waf_block

    cdn_block = main_tf.split('resource "aws_cloudfront_distribution" "cdn"', 1)[1]
    assert "web_acl_id      = var.enable_waf ? aws_wafv2_web_acl.cdn[0].arn : null" in cdn_block
    assert 'output "waf_web_acl_arn"' in outputs_tf


def test_cloudfront_to_alb_origin_cloaking_prevents_direct_waf_bypass():
    """
    When origin_verify_secret is configured, CloudFront injects X-Origin-Verify and
    ALB listeners default to HTTP 403 fixed-response unless X-Origin-Verify matches.
    """
    main_tf = (TERRAFORM_DIR / "main.tf").read_text(encoding="utf-8")
    variables_tf = (TERRAFORM_DIR / "variables.tf").read_text(encoding="utf-8")
    deploy = yaml.safe_load(DEPLOY_WORKFLOW.read_text(encoding="utf-8"))

    assert 'variable "origin_verify_secret"' in variables_tf
    assert "sensitive   = true" in variables_tf

    assert 'name  = "X-Origin-Verify"' in main_tf
    assert 'http_header_name = "X-Origin-Verify"' in main_tf
    assert 'resource "aws_lb_listener_rule" "http_origin_verify"' in main_tf
    assert 'resource "aws_lb_listener_rule" "https_origin_verify"' in main_tf
    assert 'status_code  = "403"' in main_tf

    assert "CLOUDFRONT_DOMAIN" in deploy["env"]


def test_dockerignore_excludes_git_and_preserves_explorer_console_asset():
    """
    ExplorerConsoleView serves BASE_DIR / 'docs' / 'api-explorer.html' at runtime.
    .dockerignore must exclude .git/ and docs/* while explicitly retaining
    !docs/api-explorer.html so GET /explorer/ never raises FileNotFoundError in ECS.
    """
    lines = [
        line.strip()
        for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert ".git/" in lines
    assert (
        "docs/" not in lines
    ), "Bare 'docs/' blocks BuildKit from matching !docs/api-explorer.html"
    assert "docs/*" in lines
    assert "!docs/api-explorer.html" in lines
    assert lines.index("docs/*") < lines.index("!docs/api-explorer.html")
    assert (REPO_ROOT / "docs" / "api-explorer.html").is_file()


def test_dockerfile_enforces_readonly_root_owned_app_nologin_user_and_shm_workers():
    """
    Production container must pin slim-bookworm, run as non-login UID 1000 appuser,
    keep /app owned by root:root (read-only to appuser), pre-collect staticfiles,
    and place Gunicorn worker heartbeats in /dev/shm.
    """
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    assert "FROM python:3.12-slim-bookworm AS builder" in dockerfile
    assert "FROM python:3.12-slim-bookworm\n" in dockerfile
    assert "--uid 1000 --shell /usr/sbin/nologin appuser" in dockerfile
    assert "COPY --chown=root:root . ." in dockerfile
    assert "chown -R appuser" not in dockerfile
    assert "manage.py collectstatic --noinput" in dockerfile
    assert '"--worker-tmp-dir", "/dev/shm"' in dockerfile
    assert "USER appuser" in dockerfile


def test_ci_workflow_runs_container_build_and_live_smoke_gate():
    ci = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    docker_job = ci["jobs"]["docker"]
    joined_runs = "\n".join(step.get("run", "") for step in docker_job["steps"])
    assert "docker build -t multilingual-task-api:ci-smoke ." in joined_runs
    assert "test ! -w /app/manage.py" in joined_runs
    assert "http://127.0.0.1:18000/api/v1/live/" in joined_runs
    assert "http://127.0.0.1:18000/explorer/" in joined_runs
