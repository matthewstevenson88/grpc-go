package record

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	s2apb "google.golang.org/grpc/security/s2a/internal/proto"
)

type fakeStream struct {
	// returnInvalid is a flag indicating whether the return status of Recv is
	// OK or not.
	returnInvalid bool
	// returnRecvErr is a flag indicating whether an error should be returned by
	// Recv.
	returnRecvErr bool
}

func (fs *fakeStream) Send(req *s2apb.SessionReq) error {
	if len(req.GetResumptionTicket().InBytes) == 0 {
		return errors.New("fakeStream Send received an empty InBytes")
	}
	if req.GetResumptionTicket().ConnectionId == 0 {
		return errors.New("fakeStream Send received a 0 ConnectionId")
	}
	if req.GetResumptionTicket().LocalIdentity == nil {
		return errors.New("fakeStream Send received an empty LocalIdentity")
	}
	return nil
}

func (fs *fakeStream) Recv() (*s2apb.SessionResp, error) {
	if fs.returnRecvErr {
		return nil, errors.New("fakeStream Recv error")
	}
	if fs.returnInvalid {
		return &s2apb.SessionResp{
			Status: &s2apb.SessionStatus{Code: uint32(codes.InvalidArgument)},
		}, nil
	}
	return &s2apb.SessionResp{
		Status: &s2apb.SessionStatus{Code: uint32(codes.OK)},
	}, nil
}

func TestWriteTicketsToStream(t *testing.T) {
	for _, tc := range []struct {
		returnInvalid   bool
		returnRecvError bool
	}{
		{
			// Both flags are set to false.
		},
		{
			returnInvalid: true,
		},
		{
			returnRecvError: true,
		},
	} {
		sender := ticketSender{
			connectionID: 1,
			localIdentity: &s2apb.Identity{
				IdentityOneof: &s2apb.Identity_SpiffeId{
					SpiffeId: "test_spiffe_id",
				},
			},
		}
		fs := &fakeStream{returnInvalid: tc.returnInvalid, returnRecvErr: tc.returnRecvError}
		if got, want := sender.writeTicketsToStream(fs, make([][]byte, 1)) == nil, !tc.returnRecvError && !tc.returnInvalid; got != want {
			t.Errorf("sender.writeTicketsToStream(%v, _) = (err=nil) = %v, want %v", fs, got, want)
		}
	}
}
