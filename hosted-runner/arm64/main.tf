resource "aws_instance" "orb-devops" {
  ami             = lookup(var.amis, var.aws_region)
  instance_type   = var.instance_type
  security_groups = [aws_security_group.sg_SelfRunner_arm64.id]
  key_name        = var.key_name
  user_data       = file("user_data.sh")
  associate_public_ip_address = true
  subnet_id       = "subnet-090c967a67234e472"

  tags = {
    Name            = "orb-pktvisor-self-runner"
    Provider        = "terraform"
    Role            = "test"
  }
}

