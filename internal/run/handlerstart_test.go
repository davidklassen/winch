package run_test

import (
	"slices"
	"testing"

	"github.com/davidklassen/winch/internal/fakehost"
)

// spec: Modules/service and unit (restarted and reloaded); Handlers
func TestHandlerAfterStart(t *testing.T) {
	const conf = "  - file:\n      path: /etc/app.conf\n      content: \"app\\n\"\n    notify: restart\n"
	const start = "  - service:\n      name: app\n      running: true\n"
	const restart = "handlers:\n  restart:\n    - service:\n        name: app.service\n        restarted: true\n"
	const stamp = "handlers:\n  restart:\n    - file:\n        path: /etc/app.stamp\n        content: \"x\\n\"\n    - service:\n        name: app\n        restarted: true\n"
	const reload = "handlers:\n  restart:\n    - service:\n        name: app\n        reloaded: true\n"
	pending := func(h *fakehost.Hosts) {
		h.SetFile("web1", "/etc/app.conf", "app\n")
		h.SetPending("web1", "app.restart")
	}
	const oneStage = "stages:\n  - name: s\n    hosts: all\n    steps:\n      - recipe: app\n"
	tests := []struct {
		name     string
		pipeline string
		recipes  map[string]string
		setup    func(*fakehost.Hosts)
		want     []string
	}{
		{"a start after the notify", oneStage, map[string]string{"app": "steps:\n" + conf + start + restart}, nil,
			[]string{"app start"}},
		{"a start after the notify skips a reload", oneStage, map[string]string{"app": "steps:\n" + conf + start + reload}, nil,
			[]string{"app start"}},
		{"a notify after the start", oneStage, map[string]string{"app": "steps:\n" + start + conf + restart}, nil,
			[]string{"app start", "app.service restart"}},
		{"a start in an earlier stage", "stages:\n  - name: a\n    hosts: all\n    steps:\n      - recipe: run\n  - name: b\n    hosts: all\n    steps:\n      - recipe: app\n",
			map[string]string{"run": "steps:\n" + start, "app": "steps:\n" + conf + restart}, nil,
			[]string{"app start", "app.service restart"}},
		{"a pending notify without a start", oneStage, map[string]string{"app": "steps:\n  - file:\n      path: /etc/app.conf\n      content: \"app\\n\"\n" + restart}, pending,
			[]string{"app.service restart"}},
		{"a pending notify and a start", oneStage, map[string]string{"app": "steps:\n" + start + restart}, pending,
			[]string{"app start"}},
		{"a notify after the start and an earlier notify", oneStage, map[string]string{"app": "steps:\n" + conf + start + "  - file:\n      path: /etc/app2.conf\n      content: \"app\\n\"\n    notify: restart\n" + restart}, nil,
			[]string{"app start", "app.service restart"}},
		{"a start of another unit", oneStage, map[string]string{"app": "steps:\n" + conf + "  - service:\n      name: other\n      running: true\n" + restart}, nil,
			[]string{"other start", "app.service restart"}},
		{"an earlier handler step changed", oneStage, map[string]string{"app": "steps:\n" + conf + start + stamp}, nil,
			[]string{"app start", "app restart"}},
		{"a handler step with confirm_access", oneStage, map[string]string{"app": "steps:\n" + conf + start + "handlers:\n  restart:\n    - service:\n        name: app\n        restarted: true\n      confirm_access: true\n"}, nil,
			[]string{"app start", "app restart", "confirm"}},
		{"an earlier handler step is ok", oneStage, map[string]string{"app": "steps:\n" + conf + start + stamp}, func(h *fakehost.Hosts) { h.SetFile("web1", "/etc/app.stamp", "x\n") },
			[]string{"app start"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"pipelines/site.yaml": tc.pipeline}
			for name, r := range tc.recipes {
				files["recipes/"+name+"/recipe.yaml"] = r
			}
			p := loadWeb1(t, files)
			h := fakehost.New()
			if tc.setup != nil {
				tc.setup(h)
			}
			if ok, got := applyAll(t, p, h); !ok {
				t.Fatalf("apply failed:\n%s", got)
			}
			if got := slices.DeleteFunc(h.Log["web1"], func(s string) bool { return s == "access" }); !slices.Equal(got, tc.want) {
				t.Errorf("web1 ran %q, want %q", got, tc.want)
			}
			if p := h.PendingOf("web1"); len(p) != 0 {
				t.Errorf("pending handlers after the run = %v", p)
			}
		})
	}
}
