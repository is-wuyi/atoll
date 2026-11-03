package client

// PinnedMasterOrigin is the secure transport's construction-time origin.
// Diagnostic callers must not classify requests from the mutable MasterURL.
func (c *Client) PinnedMasterOrigin() string {
	if c == nil {
		return ""
	}
	return c.pinnedMasterOrigin()
}
