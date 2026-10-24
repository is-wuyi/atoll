package client

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"atoll/pkg/types"
)

func (c *Client) waitPlannedChunk(ctx context.Context, upload types.WriteUpload, index int) error {
	q := url.Values{}
	q.Set("upload_id", strconv.FormatUint(upload.ID, 10))
	q.Set("plan_id", upload.PlanID)
	q.Set("revision", strconv.FormatUint(upload.Revision, 10))
	for {
		var status types.WriteStatus
		if err := c.writeJSON(ctx, http.MethodGet, "/writes/status?"+q.Encode(), nil, &status); err != nil {
			if !retryWriteMetadata(err) {
				return err
			}
		} else {
			if status.UploadID != upload.ID {
				return errors.New("write status differs from upload")
			}
			for _, chunk := range status.Chunks {
				if chunk.Index == index && chunk.Ready {
					return nil
				}
			}
		}
		if err := waitWriteRetry(ctx, 100*time.Millisecond); err != nil {
			return err
		}
	}
}
