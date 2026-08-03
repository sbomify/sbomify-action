// A small application for the ecosystem matrix: real dependencies with a
// transitive closure of their own, and actual source, which is what a real
// Go repository looks like.
package main

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type config struct {
	Name string `yaml:"name"`
}

func main() {
	var c config
	_ = yaml.Unmarshal([]byte("name: sbomify"), &c)
	logrus.WithField("id", uuid.New().String()).Info(fmt.Sprintf("hello %s", c.Name))
}
