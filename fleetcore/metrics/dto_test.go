package metrics

import (
	"fmt"
	"sort"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// dtoMetric reads a const metric back into name, labels and value.
type dtoMetric struct {
	name   string
	labels map[string]string
	value  float64
}

func (d *dtoMetric) read(m prometheus.Metric) error {
	var out dto.Metric
	if err := m.Write(&out); err != nil {
		return err
	}
	desc := m.Desc().String()
	// Desc{fqName: "fleetcore_x", help: ...
	i := strings.Index(desc, `fqName: "`) + len(`fqName: "`)
	d.name = desc[i : i+strings.Index(desc[i:], `"`)]
	d.labels = map[string]string{}
	for _, l := range out.Label {
		d.labels[l.GetName()] = l.GetValue()
	}
	switch {
	case out.Gauge != nil:
		d.value = out.Gauge.GetValue()
	case out.Counter != nil:
		d.value = out.Counter.GetValue()
	default:
		return fmt.Errorf("unsupported metric type")
	}
	return nil
}

func (d *dtoMetric) key() string {
	var ls []string
	for k, v := range d.labels {
		ls = append(ls, k+"="+v)
	}
	sort.Strings(ls)
	return d.name + "{" + strings.Join(ls, ",") + "}"
}
