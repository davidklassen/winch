package run

import (
	"slices"
	"testing"

	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/protocol"
)

// spec: Modules/assert ("when the step is gone from the project"); Running a pipeline/Health gates
func TestGoneCheckPlaces(t *testing.T) {
	assert, file := project.Step{Module: "assert"}, project.Step{Module: "file"}
	app := &project.Recipe{Name: "app", Steps: []project.Step{file, assert},
		Handlers: []*project.Handler{{Name: "reload", Steps: []project.Step{assert, file}}}}
	pl := &project.Pipeline{Name: "site", Stages: []project.Stage{
		{Name: "base", Pipeline: "site", Health: &project.Health{Command: "true"}, Steps: []project.Step{{Recipe: app}, assert}},
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
		{"an assert of another pipeline", protocol.Check{Pipeline: "mail", Stage: "base", Step: 1}, false},
		{"an assert of a stage", protocol.Check{Pipeline: "site", Stage: "base", Step: 2}, false},
		{"a stage step that is no assert", protocol.Check{Pipeline: "site", Stage: "base", Step: 1}, true},
		{"an assert of a recipe", protocol.Check{Recipe: "app", Step: 2}, false},
		{"a recipe step that is no assert", protocol.Check{Recipe: "app", Step: 1}, true},
		{"a recipe step that is gone", protocol.Check{Recipe: "app", Step: 3}, true},
		{"a recipe record without a step", protocol.Check{Recipe: "app"}, true},
		{"a recipe that the pipeline does not run", protocol.Check{Recipe: "mail", Step: 5}, false},
		{"an assert of a handler", protocol.Check{Recipe: "app", Handler: "reload", Step: 1}, false},
		{"a handler step that is no assert", protocol.Check{Recipe: "app", Handler: "reload", Step: 2}, true},
		{"a handler that is gone", protocol.Check{Recipe: "app", Handler: "restart", Step: 1}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := goneChecks(pl, []protocol.Check{tt.check})
			if gone := slices.Contains(got, tt.check); gone != tt.gone {
				t.Errorf("gone %v, want %v", gone, tt.gone)
			}
		})
	}
}
