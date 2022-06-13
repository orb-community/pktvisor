variable "aws_access_key" {
  default = "AWSID"
}
variable "aws_secret_key" {
  default = "AWSSECRET"
}

variable "aws_region" {
  default = "us-west-2"
}

variable "amis" {
  type    = map
  default = {
//   us-east-1 = "ami-0c4f7023847b90238" //ubuntu 20.04 amd64
    us-west-2 = "ami-025fc2c61f9333edc" //ubuntu 20.04 arm64 on us-west-2
  }
}

variable "key_name" {
  default = "devops-key"
}

variable "instance_type" {
//  default = "t3a.medium"
   default = "a1.large"
}
