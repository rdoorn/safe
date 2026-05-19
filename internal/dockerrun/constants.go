package dockerrun

// BootstrapPort is the in-container TCP port safe-init listens on
// during the one-shot keyholder-secret bootstrap. Host maps
// 127.0.0.1:<ephemeral-host-port> -> this container port via docker -p.
const BootstrapPort = "9099"

// KeyholderEnabled gates the auth bootstrap on the host side
// (port publish + agent env overrides + pipeAuthSecret goroutine).
// TEMP DEBUG (2026-05-19): disabled while verifying claude can render
// its UI inside the SAFE sandbox. The matching switch on the container
// side is `keyholderEnabled` in cmd/safe-init/main.go; the two MUST be
// kept in lockstep.
const KeyholderEnabled = false
