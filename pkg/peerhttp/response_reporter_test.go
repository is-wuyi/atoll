package peerhttp

import (
	"context"
	"net/http"
	"testing"
)

func TestResponseReporterPreservesDiagnosticsAndServingFacts(t *testing.T) {
	cert := testCert(t, "peer.test")
	listener := listen(t)
	serveTLS(t, listener, cert, okHandler)
	peer := &scriptedPeer{t: t, addr: listener.Addr().String()}
	var diagnostics, responses observationSink
	_, client := peerTransport(t, cert, peer, &diagnostics)
	ctx := WithResponseReporter(context.Background(), responses.reporter().Observe)
	response, err := getWith(ctx, client, "https://"+peer.addr+"/response-observer")
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, response)
	all, completed := diagnostics.snapshot(), responses.snapshot()
	if len(all) != 2 || len(completed) != 1 || completed[0].Phase != PhaseResponse || completed[0].Identity != "peer-a" {
		t.Fatalf("composed reports differ: diagnostics=%+v response=%+v", all, completed)
	}
	if completed[0].ConnectionID != all[1].ConnectionID || completed[0].StreamID != all[1].StreamID || completed[0].RequestID != all[1].RequestID {
		t.Fatal("additional response reporter lost the serving connection facts")
	}
}

func TestResponseReporterControlContextSuppressesAdditionalObserver(t *testing.T) {
	cert := testCert(t, "peer.test")
	listener := listen(t)
	serveTLS(t, listener, cert, okHandler)
	peer := &scriptedPeer{t: t, addr: listener.Addr().String()}
	var diagnostics, responses observationSink
	_, client := peerTransport(t, cert, peer, &diagnostics)
	ctx := ControlContext(WithResponseReporter(context.Background(), responses.reporter().Observe))
	response, err := getWith(ctx, client, "https://"+peer.addr+"/control")
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, response)
	if len(diagnostics.snapshot()) != 0 || len(responses.snapshot()) != 0 {
		t.Fatal("control request inherited an application or diagnostic observer")
	}
}

func TestResponseReporterDoesNotTurnAcceptedDialIntoCompletion(t *testing.T) {
	transport, err := NewTransport(&http.Transport{})
	if err != nil {
		t.Fatal(err)
	}
	var diagnostics, responses observationSink
	ctx := WithReporter(context.Background(), diagnostics.reporter())
	ctx = WithResponseReporter(ctx, responses.reporter().Observe)
	reporter := transport.requestReporter(ctx)
	reporter.Observe(Observation{Phase: PhaseDial, Path: PathDirect, Identity: "peer-a"})
	reporter.Observe(Observation{Master: true, Path: PathHTTPS})
	reporter.Observe(Observation{Phase: PhaseResponse, Path: PathRelay, ErrorKind: ErrorRead})
	if len(diagnostics.snapshot()) != 3 || len(responses.snapshot()) != 1 || responses.snapshot()[0].ErrorKind != ErrorRead {
		t.Fatal("response observer received a dial or control event instead of a serving response")
	}
}
