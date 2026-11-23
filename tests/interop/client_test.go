// Executed by Go's overlay mechanism inside the immutable GRIDAPPS-D client checkout.
package inverter

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestRustPeerDERControl(t *testing.T) {
	client, err := NewSEP2Client(SimConfig{ServerURL: os.Getenv("SEP_INTEROP_URL"), CertFile: os.Getenv("SEP_INTEROP_CERT"), KeyFile: os.Getenv("SEP_INTEROP_KEY"), CAFile: os.Getenv("SEP_INTEROP_CA")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dcap, err := client.Discover(ctx)
	if err != nil || dcap.EndDeviceListLink == nil {
		t.Fatalf("capability discovery: %v", err)
	}
	device, _, err := client.Register(ctx, dcap.EndDeviceListLink.Href)
	if err != nil || device.RegistrationLink == nil || device.FunctionSetAssignmentsListLink == nil || device.LFDI != client.LFDI() {
		t.Fatalf("registration: %v", err)
	}
	reg, err := client.GetRegistration(ctx, device.RegistrationLink.Href)
	if err != nil || reg.PIN != 111115 {
		t.Fatalf("registration PIN verification: %v", err)
	}
	fsas, _, err := client.GetFSAList(ctx, device.FunctionSetAssignmentsListLink.Href)
	if err != nil || len(fsas.FunctionSetAssignments) != 1 || fsas.FunctionSetAssignments[0].DERProgramListLink == nil {
		t.Fatalf("assignments: %v", err)
	}
	programs, _, err := client.GetDERProgramList(ctx, fsas.FunctionSetAssignments[0].DERProgramListLink.Href)
	if err != nil {
		t.Fatal(err)
	}
	if len(programs.DERProgram) != 1 || programs.DERProgram[0].DERControlListLink == nil {
		t.Fatal("program did not advertise its control list")
	}
	list, _, err := client.GetDERControlList(ctx, programs.DERProgram[0].DERControlListLink.Href)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Rejected) != 0 || len(list.DERControl) != 1 {
		t.Fatalf("unexpected controls: %+v", list)
	}
	control := list.DERControl[0]
	if control.DERControlBase == nil || control.DERControlBase.OpModMaxLimW == nil || *control.DERControlBase.OpModMaxLimW != 4321 {
		t.Fatal("unexpected control mode or value")
	}
}
