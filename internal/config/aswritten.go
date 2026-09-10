package config

// rememberFileValue records what the file said for a field the environment
// is about to replace.
func (c *Config) rememberFileValue(prior string, restore func(*Config, string)) {
	c.fromEnv = append(c.fromEnv, func(target *Config) { restore(target, prior) })
}

// AsWritten returns the configuration as the file has it, with every value
// the environment supplied put back the way the operator wrote it.
//
// The admin console rewrites the whole file from this struct whenever a
// policy change is applied. Without this the deployment's environment would
// be written into the operator's configuration on the first save: the
// container's own /certs paths, and worse, the admin password hash, the
// SMTP password and the LDAP bind password. Those are supplied by
// environment precisely so they stay out of a file that is usually in
// version control.
//
// The receiver is not modified, so this is safe to call on a live
// configuration.
func (c *Config) AsWritten() *Config {
	if c == nil || len(c.fromEnv) == 0 {
		return c
	}
	clone := *c
	// Restoring a webhook secret writes through to an element, so that one
	// slice has to be the clone's own before anything is put back.
	if len(c.Alerts.Webhooks) > 0 {
		clone.Alerts.Webhooks = append([]WebhookConfig(nil), c.Alerts.Webhooks...)
	}
	clone.fromEnv = nil
	for _, restore := range c.fromEnv {
		restore(&clone)
	}
	return &clone
}
