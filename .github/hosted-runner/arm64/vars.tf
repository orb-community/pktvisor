variable "aws_access_key" {
  default = "AWSID"
}
variable "aws_secret_key" {
  default = "AWSSECRET"
}

variable "environment" {
  default = "ENVIRONMENT"
}

variable "aws_region" {
  default = "us-east-1"
}

variable "amis" {
  type    = map
  default = {
    us-east-1 = "ami-0f9bd9098aca2d42b" //ubuntu 22.04 arm64 on us-east-1
  }
}

variable "key_name" {
  default = "devops-key"
}

variable "instance_type" {
  default = "a1.xlarge"
}
