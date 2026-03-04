package provider

import "time"

type Credentials struct {
	AccessKeyId     string
	AccessKeySecret string
	SecurityToken   string
	Expiration      time.Time

	nextRefresh time.Time
}

func (c *Credentials) DeepCopy() *Credentials {
	if c == nil {
		return nil
	}
	return &Credentials{
		AccessKeyId:     c.AccessKeyId,
		AccessKeySecret: c.AccessKeySecret,
		SecurityToken:   c.SecurityToken,
		Expiration:      c.Expiration,
		nextRefresh:     c.nextRefresh,
	}
}

func (c *Credentials) expired(now time.Time, expiryDelta time.Duration) bool {
	exp := c.Expiration
	if exp.IsZero() {
		return false
	}
	if expiryDelta > 0 {
		exp = exp.Add(-expiryDelta)
	}

	return exp.Before(now) || exp.Equal(now)
}

func (c *Credentials) shouldRefresh(now time.Time) bool {
	if c.expired(now, 0) {
		return true
	}
	if c.nextRefresh.IsZero() {
		return false
	}
	return c.nextRefresh.Before(now) || c.nextRefresh.Equal(now)
}
