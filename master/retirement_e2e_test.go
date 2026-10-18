package master

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"atoll/client"
	"atoll/master/meta"
	"atoll/pkg/access"
	"atoll/pkg/types"
)

func retirementE2EWriteJSON(t *testing.T, cl *client.Client, endpoint string, body any, out any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, cl.MasterURL+endpoint, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(types.FeaturesHeader, types.WritePlanFeature)
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	result, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("%s: status=%d body=%s err=%v", endpoint, resp.StatusCode, result, err)
	}
	if out != nil {
		if err := json.Unmarshal(result, out); err != nil {
			t.Fatal(err)
		}
	}
}

func retirementE2EUpload(t *testing.T, c *secCluster, cl *client.Client, data []byte, name string) (types.WriteUpload, types.PlanWriteChunkResponse) {
	t.Helper()
	var begun types.BeginWriteResponse
	retirementE2EWriteJSON(t, cl, "/writes", types.BeginWriteRequest{Path: name, OpID: "begin-" + name, Size: int64(len(data))}, &begun)
	binding := types.WriteBinding{UploadID: begun.Upload.ID, PlanID: begun.Upload.PlanID, Revision: begun.Upload.Revision}
	var planned types.PlanWriteChunkResponse
	retirementE2EWriteJSON(t, cl, "/writes/chunks", types.PlanWriteChunkRequest{WriteBinding: binding, LogicalSize: int64(len(data)), StoredSize: int64(len(data)), Encoding: types.PlainEncoding, Checksum: types.CRC32C(data)}, &planned)
	for _, node := range planned.Nodes {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, fmt.Sprintf("http://%s/objects/%d", node.Addr, planned.Plan.Object.ID), bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(types.ChecksumHeader, fmt.Sprintf("%08x", types.CRC32C(data)))
		resp, err := cl.HTTP.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusCreated {
			t.Fatalf("object upload: %d %s %v", resp.StatusCode, body, err)
		}
		verify, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, fmt.Sprintf("http://%s/verify/%d", node.Addr, planned.Plan.Object.ID), nil)
		verified, err := c.srv.nodeHTTPClient(5 * time.Second).Do(verify)
		if err != nil {
			t.Fatal(err)
		}
		verifiedBody, _ := io.ReadAll(verified.Body)
		verified.Body.Close()
		if verified.StatusCode != http.StatusOK {
			t.Fatalf("verify upload: %d %s", verified.StatusCode, verifiedBody)
		}
	}
	return begun.Upload, planned
}

func retirementE2ECluster(t *testing.T) (*secCluster, *client.Client, *Scanner) {
	t.Helper()
	c := newSecureCluster(t, 1)
	if err := c.srv.EnableWritePlanning(WritePlanningConfig{MaxReplicas: 1}); err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(c.store, time.Hour, time.Hour, time.Hour)
	c.srv.SetScanner(scanner)
	c.srv.AttachSecureTransports()
	cl, _ := c.adminLogin()
	return c, cl, scanner
}

func TestSecureRetirementAbortReleasesOnlyAfterDurableNodeReceipt(t *testing.T) {
	c, cl, scanner := retirementE2ECluster(t)
	data := []byte("unpublished authenticated object")
	u, p := retirementE2EUpload(t, c, cl, data, "/abort-object")
	node := c.nodes[0]
	objectID := p.Plan.Object.ID
	if raw, err := os.ReadFile(secureDiskObject(node, objectID)); err != nil || !bytes.Equal(raw, data) {
		t.Fatalf("planned object did not reach its real node: %v", err)
	}
	binding := types.WriteBinding{UploadID: u.ID, PlanID: u.PlanID, Revision: u.Revision}
	retirementE2EWriteJSON(t, cl, "/writes/abort", binding, nil)
	if _, err := c.store.GetInode(u.ID); !errors.Is(err, meta.ErrNotExist) {
		t.Fatalf("aborted staging reference survived: %v", err)
	}
	before, err := c.store.AutonomySnapshot()
	if err != nil || before.Capacity[0].Reserved != int64(len(data)) {
		t.Fatalf("abort released uncertain bytes: %+v %v", before.Capacity, err)
	}
	if count, err := scanner.RunRetirements(t.Context()); err != nil || count != 1 {
		t.Fatalf("retirement: count=%d err=%v", count, err)
	}
	if _, err := os.Stat(secureDiskObject(node, objectID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired object survived: %v", err)
	}
	fence := filepath.Join(node.node.DataDirForTest(), "fences", fmt.Sprintf("%02x", objectID%256), fmt.Sprint(objectID))
	if _, err := os.Stat(fence); err != nil {
		t.Fatalf("node did not persist retirement fence: %v", err)
	}
	after, err := c.store.AutonomySnapshot()
	if err != nil || after.Capacity[0].Reserved != 0 || after.Capacity[0].Accounted != 0 {
		t.Fatalf("confirmed object remains charged: %+v %v", after.Capacity, err)
	}
	records, err := c.store.ListRetirements()
	if err != nil || len(records) != 1 || records[0].State != meta.RetirementConfirmed || records[0].Receipt == nil {
		t.Fatalf("missing durable receipt: %+v %v", records, err)
	}
	if count, err := scanner.RunRetirements(t.Context()); err != nil || count != 0 {
		t.Fatalf("confirmed retirement dispatched twice: count=%d err=%v", count, err)
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPut, node.server.URL+fmt.Sprintf("/objects/%d", objectID), bytes.NewReader(data))
	response, err := cl.HTTP.Do(req)
	if response != nil {
		response.Body.Close()
		if response.StatusCode < 400 {
			t.Fatal("late object request was accepted")
		}
	} else if err == nil {
		t.Fatal("late write was not rejected")
	}
	if _, err := os.Stat(secureDiskObject(node, objectID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("late write resurrected a retired object")
	}
}

func TestSecureRetirementKeepsDetachedPublishedVersions(t *testing.T) {
	c, cl, scanner := retirementE2ECluster(t)
	first, err := cl.PutSmall("/versioned", []byte("first version"), 1, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cl.PutSmall("/versioned", []byte("second version"), 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || second.Generation != first.Generation+1 {
		t.Fatal("overwrite changed the logical file identity")
	}
	records, err := c.store.ListRetirements()
	if err != nil || len(records) != 1 || records[0].State != meta.RetirementHeld || records[0].ObjectID != first.Chunks[0].ID {
		t.Fatalf("old published content was not held: %+v %v", records, err)
	}
	if count, err := scanner.RunRetirements(t.Context()); err != nil || count != 0 {
		t.Fatalf("held published version was retired: count=%d err=%v", count, err)
	}
	for id, expected := range map[uint64]string{first.Chunks[0].ID: "first version", second.Chunks[0].ID: "second version"} {
		got, err := os.ReadFile(secureDiskObject(c.nodes[0], id))
		if err != nil || string(got) != expected {
			t.Fatalf("published object %d lost: %q %v", id, got, err)
		}
	}
}

func TestSecureRetirementControlTicketBindsCurrentAttemptAndBody(t *testing.T) {
	c, cl, _ := retirementE2ECluster(t)
	_, token := c.adminLogin()
	data := []byte("ticket bound retirement")
	u, p := retirementE2EUpload(t, c, cl, data, "/ticket-object")
	binding := types.WriteBinding{UploadID: u.ID, PlanID: u.PlanID, Revision: u.Revision}
	retirementE2EWriteJSON(t, cl, "/writes/abort", binding, nil)
	node := c.nodes[0]
	req, claimed, err := c.store.ClaimRetirement(p.Plan.Object.ID, node.node.NodeIDForTest(), time.Now(), time.Minute, time.Hour)
	if err != nil || !claimed {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	raw, _ := json.Marshal(req)
	ticketRequest := access.TicketRequest{NodeAddr: node.addr(), Method: http.MethodPost, Path: types.RetirementPath(req.ObjectID), PlanID: req.FenceID, BodyHash: meta.BodySHA256(raw)}
	if _, err := c.store.IssueUserTicket(token, c.mustAdminUser().PersonalSpaceID, ticketRequest, time.Now()); err == nil {
		t.Fatal("user was authorized to physically retire objects")
	}
	if _, err := c.store.IssueControlTicket(access.TicketRequest{NodeAddr: node.addr(), Method: http.MethodDelete, Path: fmt.Sprintf("/objects/%d", req.ObjectID)}, time.Now()); err == nil {
		t.Fatal("unfenced control DELETE was authorized")
	}
	ticket, err := c.store.IssueControlTicket(ticketRequest, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	changed := req
	changed.AttemptID = "changed-attempt-12345678"
	changedRaw, _ := json.Marshal(changed)
	bad, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, node.server.URL+ticketRequest.Path, bytes.NewReader(changedRaw))
	bad.Header.Set("Authorization", "Bearer "+ticket.Token)
	bad.Header.Set(access.PlanHeader, req.FenceID)
	response, err := http.DefaultClient.Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode < 400 {
		t.Fatal("changed body passed retirement authorization")
	}
	good, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, node.server.URL+ticketRequest.Path, bytes.NewReader(raw))
	good.Header.Set("Authorization", "Bearer "+ticket.Token)
	good.Header.Set(access.PlanHeader, req.FenceID)
	response, err = http.DefaultClient.Do(good)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	var receipt types.ObjectRetirementReceipt
	if readErr != nil || response.StatusCode != http.StatusOK || types.DecodeRetirementJSON(body, &receipt) != nil {
		t.Fatalf("valid retirement denied: %d %s %v", response.StatusCode, body, readErr)
	}
	if ok, err := c.store.ConfirmRetirement(receipt, time.Now(), time.Hour); err != nil || !ok {
		t.Fatalf("valid retirement receipt: %v %v", ok, err)
	}
	stale, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, node.server.URL+ticketRequest.Path, bytes.NewReader(raw))
	stale.Header.Set("Authorization", "Bearer "+ticket.Token)
	stale.Header.Set(access.PlanHeader, req.FenceID)
	response, err = http.DefaultClient.Do(stale)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode < 400 {
		t.Fatal("confirmed retirement ticket remained valid")
	}
}
