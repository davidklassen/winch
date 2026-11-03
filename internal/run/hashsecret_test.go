package run

import (
	"bytes"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
)

// secretPlan returns a plan with one file step that reads the secret value,
// with the old content old, of a project whose inventory has the SHA-256 inv.
func secretPlan(value, old, inv string) *Plan {
	st := project.Step{
		Module: "file",
		Args:   &module.File{Path: "/etc/" + value, Data: []byte("password " + value + "\n")},
		Then:   "passwd " + value,
		Parts:  []string{value},
	}
	res := module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"owner root → u" + value}, Old: &old}
	h := project.Host{Name: "web1"}
	return &Plan{
		Project: "acme",
		Hosts:   []project.Host{h},
		Stages: []StagePlan{{Stage: &project.Stage{Name: "base"}, Hosts: []HostPlan{{Host: h, Steps: []Planned{
			{Step: st, Result: res, Address: "base#1"},
		}}}}},
		sums: map[string]string{"inventories/test.yaml": inv},
	}
}

// spec: Running a pipeline/Plan ("A secret enters the hash through its value")
func TestHashSecretValue(t *testing.T) {
	a := secretPlan("hunter2", "password hunter2 old\n", "sum1").HashInput()
	if b := secretPlan("swordfish", "password hunter2 old\n", "sum1").HashInput(); bytes.Equal(a, b) {
		t.Errorf("a step that reads another secret has the same hash input:\n%s", a)
	}
	for name, set := range map[string]func(st *project.Step){
		"args": func(st *project.Step) {
			st.Args = &module.File{Path: "/etc/swordfish", Data: []byte("password hunter2\n")}
		},
		"then": func(st *project.Step) { st.Then = "passwd swordfish" },
	} {
		p := secretPlan("hunter2", "password hunter2 old\n", "sum1")
		set(&p.Stages[0].Hosts[0].Steps[0].Step)
		if bytes.Equal(a, p.HashInput()) {
			t.Errorf("another secret in the %s only did not change the hash input", name)
		}
	}
	if b := secretPlan("hunter2", "password hunter2 old\n", "sum2").HashInput(); bytes.Equal(a, b) {
		t.Errorf("a new inventory file did not change the hash input:\n%s", a)
	}
}

// spec: Running a pipeline/Plan ("the check results")
func TestHashSecretResult(t *testing.T) {
	a := secretPlan("hunter2", "password hunter2 old\n", "sum1")
	if b := secretPlan("hunter2", "password swordfish old\n", "sum1"); bytes.Equal(a.HashInput(), b.HashInput()) {
		t.Errorf("the old content of a step that reads a secret did not enter the hash input:\n%s", a.HashInput())
	}
	b := secretPlan("hunter2", "password hunter2 old\n", "sum1")
	b.Stages[0].Hosts[0].Steps[0].Result.Changes = []string{"owner root → u" + "hunter2", "mode 0644"}
	if bytes.Equal(a.HashInput(), b.HashInput()) {
		t.Error("other changes of a step that reads a secret did not change the hash input")
	}
}
