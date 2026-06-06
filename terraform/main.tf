terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket         = "loganalyzer-tf-state"
    key            = "ai-log-analyzer/terraform.tfstate"
    region         = "ap-south-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}

provider "aws" {
  region = var.aws_region
}

# ── Variables ────────────────────────────────────────────────────────────────

variable "aws_region" {
  type    = string
  default = "ap-south-1"
}

variable "lambda_function_name" {
  type    = string
  default = "ai-log-analyzer"
}

variable "log_groups_to_monitor" {
  type        = list(string)
  description = "CloudWatch Log Groups to attach subscription filters to"
  default     = [
    "/aws/lambda/ai-log-analyzer",
  ]
}

variable "subscription_filter_pattern" {
  type    = string
  default = "?ERROR ?Exception ?CRITICAL ?fatal"
}

variable "lambda_timeout" {
  type    = number
  default = 120
}

variable "lambda_memory_mb" {
  type    = number
  default = 512
}

variable "environment" {
  type    = string
  default = "production"
}

variable "alert_email" {
  type        = string
  description = "Email address to subscribe to the alert SNS topic (leave empty to skip)"
  default     = "soumya.pratik2@gmail.com"
}

# ── Data sources ─────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}

# ── SSM Parameters ───────────────────────────────────────────────────────────

resource "aws_ssm_parameter" "gemini_api_key" {
  name        = "/${var.environment}/ai-log-analyzer/gemini-api-key"
  description = "Google Gemini API key for AI Log Analyzer"
  type        = "SecureString"
  value       = "REPLACE_ME_AFTER_DEPLOY"
  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "slack_webhook_url" {
  name        = "/${var.environment}/ai-log-analyzer/slack-webhook-url"
  description = "Slack Incoming Webhook URL for alert notifications"
  type        = "SecureString"
  value       = "REPLACE_ME_AFTER_DEPLOY"
  lifecycle {
    ignore_changes = [value]
  }
}

# ── Lambda Layer (dependencies) ───────────────────────────────────────────────

resource "aws_lambda_layer_version" "dependencies" {
  filename            = "${path.module}/../layer.zip"
  layer_name          = "${var.lambda_function_name}-dependencies"
  description         = "anthropic and boto3 for AI Log Analyzer"
  compatible_runtimes = ["python3.12"]
  source_code_hash    = filebase64sha256("${path.module}/../layer.zip")

  lifecycle {
    create_before_destroy = true
  }
}

# ── IAM Role ─────────────────────────────────────────────────────────────────

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${var.lambda_function_name}-exec-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "lambda_permissions" {
  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"]
  }

  statement {
    sid    = "SSMParameters"
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
    ]
    resources = [
      aws_ssm_parameter.gemini_api_key.arn,
      aws_ssm_parameter.slack_webhook_url.arn,
    ]
  }

  statement {
    sid    = "SNSPublish"
    effect = "Allow"
    actions = [
      "sns:Publish",
    ]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid    = "KMSDecrypt"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
    ]
    resources = ["arn:aws:kms:${var.aws_region}:${data.aws_caller_identity.current.account_id}:alias/aws/ssm"]
  }
}

resource "aws_iam_role_policy" "lambda_inline" {
  name   = "${var.lambda_function_name}-policy"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}

# ── Lambda Function ───────────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${var.lambda_function_name}"
  retention_in_days = 30
  tags              = local.common_tags
}

resource "aws_lambda_function" "analyzer" {
  filename         = "${path.module}/../function.zip"
  function_name    = var.lambda_function_name
  role             = aws_iam_role.lambda_exec.arn
  handler          = "src/handlers/log_analyzer.handler"
  runtime          = "python3.12"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_mb
  source_code_hash = filebase64sha256("${path.module}/../function.zip")
  layers           = [aws_lambda_layer_version.dependencies.arn]

  environment {
    variables = {
      GEMINI_API_KEY_SSM_PATH    = aws_ssm_parameter.gemini_api_key.name
      SLACK_WEBHOOK_URL_SSM_PATH = aws_ssm_parameter.slack_webhook_url.name
      ALERT_SNS_TOPIC_ARN        = aws_sns_topic.alerts.arn
      LOG_LEVEL                  = "INFO"
      ENVIRONMENT                = var.environment
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda_logs,
    aws_iam_role_policy.lambda_inline,
  ]

  tags = local.common_tags
}

# ── SNS Topic (outbound alerts — email/SMS subscribers) ──────────────────────

resource "aws_sns_topic" "alerts" {
  name = "${var.lambda_function_name}-alert-notifications"
  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "alert_email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ── SNS Topic (CloudWatch Alarm notifications) ────────────────────────────────

resource "aws_sns_topic" "alarms" {
  name = "${var.lambda_function_name}-alarms"
  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.analyzer.arn
}

resource "aws_lambda_permission" "sns_invoke" {
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.analyzer.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.alarms.arn
}

# ── CloudWatch Logs Subscription Filters ─────────────────────────────────────

resource "aws_lambda_permission" "cwl_invoke" {
  for_each      = toset(var.log_groups_to_monitor)
  statement_id  = "AllowCWLInvoke-${replace(each.key, "/", "-")}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.analyzer.function_name
  principal     = "logs.${var.aws_region}.amazonaws.com"
  source_arn    = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:${each.key}:*"
}

resource "aws_cloudwatch_log_subscription_filter" "monitor" {
  for_each        = toset(var.log_groups_to_monitor)
  name            = "${var.lambda_function_name}-filter-${index(var.log_groups_to_monitor, each.key)}"
  log_group_name  = each.key
  filter_pattern  = var.subscription_filter_pattern
  destination_arn = aws_lambda_function.analyzer.arn

  depends_on = [aws_lambda_permission.cwl_invoke]
}

# ── Example CloudWatch Alarm ──────────────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.lambda_function_name}-high-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "Lambda error rate exceeded threshold — triggering AI log analysis"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = var.lambda_function_name
  }

  tags = local.common_tags
}

# ── Locals ────────────────────────────────────────────────────────────────────

locals {
  common_tags = {
    Project     = "ai-log-analyzer"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "lambda_function_arn" {
  value = aws_lambda_function.analyzer.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.analyzer.function_name
}

output "sns_topic_arn" {
  value = aws_sns_topic.alarms.arn
}

output "ssm_gemini_api_key_path" {
  value = aws_ssm_parameter.gemini_api_key.name
}

output "alert_sns_topic_arn" {
  value       = aws_sns_topic.alerts.arn
  description = "SNS topic ARN for alert notifications — subscribe email/SMS addresses here"
}

output "ssm_slack_webhook_path" {
  value = aws_ssm_parameter.slack_webhook_url.name
}
