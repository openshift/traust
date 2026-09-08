package rules

import (
	"context"
	"net/http"
	"os/exec"
)

// stand-in for github.com/gorilla/mux so the fixture stays stdlib-only;
// the rules match on the call shape `mux.Vars(r)`, not the import.
var mux muxShim

type muxShim struct{}

func (muxShim) Vars(*http.Request) map[string]string { return nil }

func execTaint(w http.ResponseWriter, r *http.Request) {
	// ruleid: traust-go-injection-exec-taint
	exec.Command("kubectl", "get", r.URL.Query().Get("resource"))

	// ruleid: traust-go-injection-exec-taint
	exec.CommandContext(context.TODO(), "oc", r.FormValue("verb"))

	v := mux.Vars(r)
	// ruleid: traust-go-injection-exec-taint
	exec.Command("tool", v["name"])

	// ok: traust-go-injection-exec-taint
	exec.Command("kubectl", "get", "pods")
}

func shellC(dynamic string) {
	// ruleid: traust-go-injection-shell-c
	exec.Command("sh", "-c", dynamic)

	// ruleid: traust-go-injection-shell-c
	exec.CommandContext(context.TODO(), "bash", "-c", "echo "+dynamic)

	// ok: traust-go-injection-shell-c
	exec.Command("sh", "-c", "systemctl restart kubelet")

	// ok: traust-go-injection-shell-c
	exec.Command("ls", "-la", dynamic)
}
