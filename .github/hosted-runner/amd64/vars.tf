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
    us-east-1 =  "ami-0557a15b87f6559cf" //ubuntu 22.04 amd64 - us-east-1 - ami-0557a15b87f6559cf
  }
}

variable "key_name" {
  default = "devops-key"
}

variable "instance_type" {
  default = "t3.xlarge"
}
