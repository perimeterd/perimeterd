package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/perimeterd/perimeterd/internal/control"
)

func runStatus(args []string, stdout, stderr io.Writer) int {
	return statusCommand(args, stdout, stderr, control.Status)
}

func statusCommand(args []string, stdout, stderr io.Writer, call func(context.Context) (control.StatusResult, error)) int {
	flags := newCommandFlags("status")
	jsonOutput := flags.fs.Bool("json", false, "print the complete status report as JSON")
	flags.fs.Usage = func() {
		_, _ = flags.output.WriteString("Usage: perimeterd status [--json]\nReports daemon-owned last-acknowledged state, not a kernel audit.\n")
		flags.fs.PrintDefaults()
	}
	// Buffer help so its delivery failure, like every status output failure,
	// returns 1 rather than the usage-error exit code.
	var help bytes.Buffer
	if handled, exitCode := flags.parse(args, &help, stderr); handled {
		if help.Len() != 0 {
			if _, err := io.Copy(stdout, &help); err != nil {
				_, _ = fmt.Fprintf(stderr, "perimeterd: write status help output: %s\n", err)
				return 1
			}
		}
		return exitCode
	}
	if err := requireRoot("status"); err != nil {
		_, _ = fmt.Fprintf(stderr, "perimeterd: %s\n", err)
		return 1
	}
	result, err := call(context.Background())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "perimeterd: status: %s\n", err)
		return 1
	}
	if *jsonOutput {
		err = json.NewEncoder(stdout).Encode(result)
	} else {
		err = writeStatus(stdout, result)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "perimeterd: write status output: %s\n", err)
		return 1
	}
	if !result.Successful() {
		return 1
	}
	return 0
}

func writeStatusUptime(out *strings.Builder, seconds uint64) {
	if seconds == 0 {
		out.WriteString("0s")
		return
	}
	var digits [20]byte
	for _, unit := range [...]struct {
		seconds uint64
		suffix  byte
	}{{86400, 'd'}, {3600, 'h'}, {60, 'm'}, {1, 's'}} {
		if count := seconds / unit.seconds; count != 0 {
			out.Write(strconv.AppendUint(digits[:0], count, 10))
			out.WriteByte(unit.suffix)
		}
		seconds %= unit.seconds
	}
}

func writeStatus(w io.Writer, result control.StatusResult) error {
	var out strings.Builder
	fmt.Fprintf(&out, "Daemon: version=%s uptime=", result.Daemon.Version)
	writeStatusUptime(&out, result.Daemon.UptimeSeconds)
	fmt.Fprintf(&out, " healthy=%t\n", result.Daemon.Healthy)
	fmt.Fprintf(&out, "Observed: %s (last-acknowledged daemon state; not a kernel audit)\n", result.ObservedAt.Format(time.RFC3339Nano))
	if !result.Daemon.Healthy {
		out.WriteString("WARNING: daemon health is degraded\n")
	}
	applied := result.Applied
	fmt.Fprintf(&out, "Last-applied: state=%s", applied.State)
	if applied.Revision != "" {
		fmt.Fprintf(&out, " revision=%s", applied.Revision)
	}
	if applied.ConfigEpoch != 0 {
		fmt.Fprintf(&out, " config_epoch=%d", applied.ConfigEpoch)
	}
	if applied.Manifest != "" {
		fmt.Fprintf(&out, " manifest=%s", applied.Manifest)
	}
	out.WriteByte('\n')
	if applied.State == "empty" {
		out.WriteString("No managed enforcement is applied.\n")
	}
	if applied.State == "unavailable" {
		fmt.Fprintf(&out, "WARNING: last-applied state is unavailable: %s\n", applied.Reason)
	}
	if details := applied.Details; details != nil {
		firewall := details.Firewall
		fmt.Fprintf(&out, "Firewall: backend=%s families=%s deny_action=%s\n", firewall.Backend, strings.Join(firewall.Families, ","), firewall.DenyAction)
		for _, attachment := range firewall.Attachments {
			fmt.Fprintf(&out, "Attachment: chain=%s direction=%s", attachment.Chain, attachment.Direction)
			if len(attachment.InputInterfaces) != 0 {
				fmt.Fprintf(&out, " input_interfaces=%s", strings.Join(attachment.InputInterfaces, ","))
			}
			if len(attachment.OutputInterfaces) != 0 {
				fmt.Fprintf(&out, " output_interfaces=%s", strings.Join(attachment.OutputInterfaces, ","))
			}
			fmt.Fprintf(&out, " original_destination=%t\n", attachment.OriginalDestination)
		}
		for i, policy := range details.Policies {
			fmt.Fprintf(&out, "Policy %d: name=%s priority=%d direction=%s mode=%s traffic=%s\n", i+1, policy.Name, policy.Priority, policy.Direction, policy.Mode, statusTraffic(policy.Traffic))
		}
		out.WriteString("Loaded source prefix elements (per family/source/type; not unique IPs or packet counts):\n")
		for _, count := range details.PrefixCounts {
			fmt.Fprintf(&out, "  family=%s source=%s type=%s count=%d\n", count.Family, count.Source, count.Type, count.Count)
		}
		out.WriteString("Compiled firewall sets (static target memberships; shared sets counted once; not a kernel audit):\n")
		for _, family := range [...]string{"ipv4", "ipv6"} {
			for _, set := range details.CompiledSets.Sets {
				if set.Family == family {
					fmt.Fprintf(&out, "  family=%s set=%s policies=", family, set.ID)
					if len(set.Policies) == 0 {
						out.WriteByte('-')
					}
					for i, name := range set.Policies {
						if i != 0 {
							out.WriteByte(',')
						}
						out.WriteString(name)
					}
					fmt.Fprintf(&out, " count=%d\n", set.Count)
				}
			}
			for _, total := range details.CompiledSets.Totals {
				if total.Family == family {
					fmt.Fprintf(&out, "  family=%s total_memberships=%d\n", family, total.Count)
				}
			}
		}
		out.WriteString("  Dynamic CrowdSec memberships excluded; decision counts reported separately.\n")
		crowdsec := details.CrowdSec
		if !crowdsec.Enabled {
			out.WriteString("CrowdSec: disabled\n")
		} else {
			fmt.Fprintf(&out, "CrowdSec: acknowledged_epoch=%d operation=%d validity=%s deadline=", crowdsec.Epoch, crowdsec.Operation, crowdsec.Validity)
			if crowdsec.ValidUntil.IsZero() {
				out.WriteString("none\n")
			} else {
				fmt.Fprintf(&out, "%s\n", crowdsec.ValidUntil.Format(time.RFC3339Nano))
			}
			if crowdsec.Validity == "valid" && crowdsec.Counts != nil {
				fmt.Fprintf(&out, "  Unexpired acknowledged decisions (not unique addresses): ipv4=%d ipv6=%d\n", crowdsec.Counts.IPv4, crowdsec.Counts.IPv6)
			} else if crowdsec.Validity != "valid" {
				fmt.Fprintf(&out, "WARNING: CrowdSec acknowledged state is %s; decision counts unavailable\n", crowdsec.Validity)
			}
		}
	}
	_, err := io.WriteString(w, out.String())
	return err
}

func statusTraffic(traffic control.StatusTraffic) string {
	if traffic.Any {
		return "any"
	}
	var parts []string
	for _, protocol := range []struct {
		name  string
		ports []control.StatusPortRange
	}{{"tcp", traffic.TCP}, {"udp", traffic.UDP}} {
		if len(protocol.ports) == 0 {
			continue
		}
		var ports []string
		for _, port := range protocol.ports {
			value := strconv.Itoa(int(port.Start))
			if port.End != port.Start {
				value += "-" + strconv.Itoa(int(port.End))
			}
			ports = append(ports, value)
		}
		parts = append(parts, protocol.name+":"+strings.Join(ports, ","))
	}
	if traffic.ICMP {
		parts = append(parts, "icmp")
	}
	if traffic.ICMPv6 {
		parts = append(parts, "icmpv6")
	}
	return strings.Join(parts, " ")
}
