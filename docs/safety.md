# Safety

This repository is designed for defensive local research.

- environments are simulated
- the network tool records `mock://` targets rather than making outbound requests
- the secret is an explicit mock value
- no credential collection is implemented
- no persistence or malware behavior is implemented
- no public infrastructure scanning is implemented
- attack generation targets only bundled local environments

The deliberately vulnerable proxy exists to test confused-deputy and tool-routing defenses. It must not be adapted to target systems without authorization.
