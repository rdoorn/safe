package dockerrun

// BootstrapPort is the in-container TCP port safe-init listens on
// during the one-shot keyholder-secret bootstrap. Host maps
// 127.0.0.1:<ephemeral-host-port> -> this container port via docker -p.
const BootstrapPort = "9099"
