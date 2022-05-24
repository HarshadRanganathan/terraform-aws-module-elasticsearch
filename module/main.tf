module "label" {
  source     = "git::https://github.com/HarshadRanganathan/terraform-aws-module-null-label.git//module?ref=1.0.0"
  enabled    = var.enabled
  namespace  = var.namespace
  name       = var.name
  stage      = var.stage
  delimiter  = var.delimiter
  attributes = var.attributes
  tags       = var.tags
}

module "user_label" {
  source     = "git::https://github.com/HarshadRanganathan/terraform-aws-module-null-label.git//module?ref=1.0.0"
  enabled    = var.enabled
  namespace  = var.namespace
  name       = var.name
  stage      = var.stage
  delimiter  = var.delimiter
  attributes = concat(var.attributes, ["user"])
  tags       = var.tags
}

resource "aws_security_group" "default" {
  count       = var.enabled ? 1 : 0
  vpc_id      = var.vpc_id
  name        = module.label.id
  description = "Allow inbound traffic from Security Groups and CIDRs. Allow all outbound traffic"
  tags        = module.label.tags
}

resource "aws_security_group_rule" "ingress_security_groups" {
  count                    = var.enabled ? length(var.security_groups) : 0
  description              = "Allow inbound traffic from Security Groups"
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = var.security_groups[count.index]
  security_group_id        = join("", aws_security_group.default.*.id)
}

resource "aws_security_group_rule" "ingress_cidr_blocks" {
  count             = var.enabled && length(var.allowed_cidr_blocks) > 0 ? 1 : 0
  description       = "Allow inbound traffic from CIDR blocks"
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  cidr_blocks       = var.allowed_cidr_blocks
  security_group_id = join("", aws_security_group.default.*.id)
}

resource "aws_security_group_rule" "egress" {
  count             = var.enabled ? 1 : 0
  description       = "Allow all egress traffic"
  type              = "egress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = join("", aws_security_group.default.*.id)
}

resource "aws_elasticsearch_domain" "default" {
  count                 = var.enabled ? 1 : 0
  domain_name           = module.label.id
  elasticsearch_version = var.elasticsearch_version

  advanced_options      = var.advanced_options

  advanced_security_options {
    enabled                        = var.enable_advanced_security_options
    internal_user_database_enabled = var.enable_internal_user_database
    master_user_options {
      master_user_arn      = var.master_user_arn
      master_user_name     = var.master_user_name
      master_user_password = var.master_user_password
    }
  }
  ebs_options {
    ebs_enabled = var.ebs_enabled
    volume_size = var.ebs_volume_size
    volume_type = var.ebs_volume_type
    iops        = var.ebs_iops
  }

  cognito_options {
    enabled          = var.cognito_enabled
    identity_pool_id = var.cognito_identity_pool_id
    role_arn         = var.cognito_role_arn
    user_pool_id     = var.cognito_user_pool_id
  }

  domain_endpoint_options {
    enforce_https       = var.enforce_https
    tls_security_policy = var.tls_security_policy
    custom_endpoint_certificate_arn = var.custom_endpoint_certificate_arn
    custom_endpoint_enabled = var.custom_endpoint_enabled
    custom_endpoint = var.custom_endpoint
  }
  encrypt_at_rest {
    enabled    = var.encrypt_at_rest_enabled
    kms_key_id = var.encrypt_at_rest_kms_key_id
  }

  cluster_config {
    instance_count           = var.instance_count
    instance_type            = var.instance_type
    dedicated_master_enabled = var.dedicated_master_enabled
    dedicated_master_count   = var.dedicated_master_count
    dedicated_master_type    = var.dedicated_master_type
    zone_awareness_enabled   = var.zone_awareness_enabled

    zone_awareness_config {
      availability_zone_count = var.availability_zone_count
    }
  }

  node_to_node_encryption {
    enabled = var.node_to_node_encryption_enabled
  }

  vpc_options {
    security_group_ids = [join("", aws_security_group.default.*.id)]
    subnet_ids         = var.subnet_ids
  }

  snapshot_options {
    automated_snapshot_start_hour = var.automated_snapshot_start_hour
  }

  log_publishing_options {
    enabled                  = var.log_publishing_index_enabled
    log_type                 = "INDEX_SLOW_LOGS"
    cloudwatch_log_group_arn = var.log_publishing_index_cloudwatch_log_group_arn
  }

  log_publishing_options {
    enabled                  = var.log_publishing_search_enabled
    log_type                 = "SEARCH_SLOW_LOGS"
    cloudwatch_log_group_arn = var.log_publishing_search_cloudwatch_log_group_arn
  }

  log_publishing_options {
    enabled                  = var.log_publishing_application_enabled
    log_type                 = "ES_APPLICATION_LOGS"
    cloudwatch_log_group_arn = var.log_publishing_application_cloudwatch_log_group_arn
  }

  tags = module.label.tags
}

data "aws_iam_policy_document" "default" {
  count = var.enabled && (length(var.iam_authorizing_role_arns) > 0 || length(var.iam_role_arns) > 0) ? 1 : 0

  statement {
    actions = distinct(compact(var.iam_actions))

    resources = [
      join("", aws_elasticsearch_domain.default.*.arn),
      "${join("", aws_elasticsearch_domain.default.*.arn)}/*"
    ]

    principals {
      type        = "AWS"
      identifiers = distinct(compact(var.iam_role_arns))
    }
  }
}

resource "aws_elasticsearch_domain_policy" "default" {
  count           = var.enabled && (length(var.iam_authorizing_role_arns) > 0 || length(var.iam_role_arns) > 0) ? 1 : 0
  domain_name     = module.label.id
  access_policies = join("", data.aws_iam_policy_document.default.*.json)
}

module "domain_hostname" {
  source  = "git::https://github.com/HarshadRanganathan/terraform-aws-module-route53-cluster-hostname.git//module?ref=1.0.0"
  enabled = var.enabled && var.dns_zone_id != "" ? true : false
  name    = var.es_subdomain_name
  ttl     = 60
  zone_id = var.dns_zone_id
  records = [join("", aws_elasticsearch_domain.default.*.endpoint)]
}

module "kibana_hostname" {
  source  = "git::https://github.com/HarshadRanganathan/terraform-aws-module-route53-cluster-hostname.git//module?ref=1.0.0"
  enabled = var.enabled && var.dns_zone_id != "" ? true : false
  name    = var.kibana_subdomain_name
  ttl     = 60
  zone_id = var.dns_zone_id
  records = [join("", aws_elasticsearch_domain.default.*.kibana_endpoint)]
}
