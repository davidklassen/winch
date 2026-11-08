package run

import (
	"slices"
	"testing"

	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
)

// spec: Running a pipeline/Health gates; State on the host
func TestGoneCheckPlaces(t *testing.T) {
	file := project.Step{Module: "file"}
	app := &project.Recipe{Name: "app", Steps: []project.Step{file}}
	pl := &project.Pipeline{Name: "site", Stages: []project.Stage{
		{Name: "base", Pipeline: "site", Health: &project.Health{Command: "true"}, Steps: []project.Step{{Recipe: app}, file}},
		{Name: "web", Pipeline: "site", Steps: []project.Step{file}},
	}}
	tests := []struct {
		name  string
		check protocol.Check
		gone  bool
	}{
		{"a gate", protocol.Check{Pipeline: "site", Stage: "base"}, false},
		{"a stage without a gate", protocol.Check{Pipeline: "site", Stage: "web"}, true},
		{"a stage that is gone", protocol.Check{Pipeline: "site", Stage: "db"}, true},
		{"a gate of another pipeline", protocol.Check{Pipeline: "mail", Stage: "web"}, false},
		{"a gate of a stage that another pipeline no longer has", protocol.Check{Pipeline: "mail", Stage: "db"}, true},
		{"a pipeline that the project no longer has", protocol.Check{Pipeline: "old", Stage: "web"}, true},
		{"an assert of a stage", protocol.Check{Pipeline: "site", Stage: "base", Step: 2}, true},
		{"an assert of another pipeline", protocol.Check{Pipeline: "mail", Stage: "base", Step: 1}, true},
		{"an assert of a recipe", protocol.Check{Recipe: "app", Step: 1}, true},
		{"an assert of a recipe of another pipeline", protocol.Check{Recipe: "mail", Step: 1}, true},
		{"an assert of a handler", protocol.Check{Recipe: "app", Handler: "reload", Step: 1}, true},
		{"an assert of a stage handler", protocol.Check{Pipeline: "site", Stage: "base", Handler: "reload", Step: 1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mail := &project.Pipeline{Name: "mail", Stages: []project.Stage{{Name: "web", Pipeline: "mail"}, {Name: "base", Pipeline: "mail"}}}
			o := owners{pl: pl, pipelines: map[string]*project.Pipeline{"site": pl, "mail": mail}, recipes: map[string]*project.Recipe{"app": app, "mail": {Name: "mail", Steps: []project.Step{file}}}, all: true}
			got := o.goneChecks([]protocol.Check{tt.check})
			if gone := slices.Contains(got, tt.check); gone != tt.gone {
				t.Errorf("gone %v, want %v", gone, tt.gone)
			}
		})
	}
}
