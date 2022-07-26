resource "aws_security_group" "sg_SelfRunner_amd64" {
  name        = "sg_pktvisor_SelfRunner_amd64"
  description = "Allow all outbound traffic and inbound 22/80"
  vpc_id      = "vpc-0cd4a525c008d8d71"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "SelfRunner_amd64"
    Provisioner = "terraform"

  }
}
