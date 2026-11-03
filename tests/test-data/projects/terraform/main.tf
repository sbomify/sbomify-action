terraform {
  required_providers {
    random = { source = "hashicorp/random", version = "~> 3.6" }
    null   = { source = "hashicorp/null" }
  }
}
resource "random_pet" "name" {}
