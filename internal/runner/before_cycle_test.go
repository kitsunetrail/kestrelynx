package runner

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/kitsunetrail/kestrelynx/internal/inventory"
)

// orderLister notes when the containers of a cycle are listed, and stops the
// cycle there.
type orderLister struct {
	order *[]string
}

func (l orderLister) RunningContainers(context.Context) ([]inventory.Container, error) {
	*l.order = append(*l.order, "list")
	return nil, errors.New("the cycle stops here")
}

// What must not change during a cycle is brought up to date before the cycle
// does anything else: the Runner's functions first, in order, then the one of
// the dependency update stage, which follows what they changed.
func TestRunOnceRunsBeforeCycleFirst(t *testing.T) {
	var order []string
	note := func(name string) func(context.Context) {
		return func(context.Context) { order = append(order, name) }
	}
	r := Runner{
		Lister:      orderLister{order: &order},
		Now:         clock,
		BeforeCycle: []func(context.Context){note("table"), note("second")},
		Plan:        &PlanConfig{Language: &LanguageUpdateConfig{BeforeCycle: note("stage")}},
	}
	if err := r.RunOnce(context.Background()); err == nil {
		t.Fatal("the cycle went on past the listing")
	}
	if !reflect.DeepEqual(order, []string{"table", "second", "stage", "list"}) {
		t.Fatalf("order = %v", order)
	}

	// Without the functions the cycle starts as it always did.
	order = nil
	r = Runner{Lister: orderLister{order: &order}, Now: clock}
	_ = r.RunOnce(context.Background())
	if !reflect.DeepEqual(order, []string{"list"}) {
		t.Fatalf("order without functions = %v", order)
	}
}
