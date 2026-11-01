package run

import (
	"bytes"
	"testing"

	"github.com/davidklassen/winch/internal/module"
	"github.com/davidklassen/winch/internal/project"
	"github.com/davidklassen/winch/internal/secret"
)

// secretPlan returns a plan with one file step that reads the secret value,
// with the old content old, of a project whose inventory has the SHA-256 inv.
func secretPlan(value, old, inv string) *Plan {
	f := secret.NewFilter()
	f.Add(value)
	ph := secret.Placeholder(1)
	st := project.Step{
		Module:   "file",
		Args:     &module.File{Path: "/etc/" + value, Data: []byte("password " + value + "\n")},
		Then:     "passwd " + value,
		Secret:   true,
		HashArgs: &module.File{Path: "/etc/" + ph, Data: []byte("password " + ph + "\n")},
		HashThen: "passwd " + ph,
	}
	res := module.Result{Status: module.Change, Action: module.Modify, Changes: []string{"owner root → u" + value}, Old: &old}
	h := project.Host{Name: "web1"}
	return &Plan{
		Project: "acme",
		Hosts:   []project.Host{h},
		Stages: []StagePlan{{Stage: &project.Stage{Name: "base"}, Hosts: []HostPlan{{Host: h, Steps: []Planned{
			{Step: st, Result: res, Address: "base#1"},
		}}}}},
		sums:   map[string]string{"inventories/test.yaml": inv},
		filter: f,
	}
}

// spec: Running a pipeline/Plan ("A secret enters the hash through the !secret ciphertexts")
func TestHashSecretCiphertext(t *testing.T) {
	a := secretPlan("hunter2", "password hunter2 old\n", "sum1").HashInput()
	if b := secretPlan("swordfish", "password swordfish old\n", "sum1").HashInput(); !bytes.Equal(a, b) {
		t.Errorf("two plain values in the same project files give two hash inputs:\n%s\n%s", a, b)
	}
	if b := secretPlan("hunter2", "password hunter2 old\n", "sum2").HashInput(); bytes.Equal(a, b) {
		t.Errorf("a new inventory file did not change the hash input:\n%s", a)
	}
}

// spec: Running a pipeline/Plan ("the check results"; "The old content on the host of a step that reads a secret does not enter the hash")
func TestHashSecretResult(t *testing.T) {
	a := secretPlan("hunter2", "password hunter2 old\n", "sum1")
	// The host holds an earlier value of the secret.
	if b := secretPlan("hunter2", "password swordfish old\n", "sum1"); !bytes.Equal(a.HashInput(), b.HashInput()) {
		t.Errorf("the old content of a step that reads a secret entered the hash input:\n%s\n%s", a.HashInput(), b.HashInput())
	}
	b := secretPlan("hunter2", "password hunter2 old\n", "sum1")
	b.Stages[0].Hosts[0].Steps[0].Result.Changes = []string{"owner root → u" + "hunter2", "mode 0644"}
	if bytes.Equal(a.HashInput(), b.HashInput()) {
		t.Error("other changes of a step that reads a secret did not change the hash input")
	}
}
