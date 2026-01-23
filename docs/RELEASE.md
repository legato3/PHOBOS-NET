# Release Information

## Architecture Support
PHOBOS-NET Docker images are officially published as multi-arch manifests supporting:
- **linux/amd64**: Standard 64-bit x86 servers and cloud instances.
- **linux/arm64**: ARM-based systems including Raspberry Pi 4/5, Apple Silicon (M1/M2/M3), and AWS Graviton.

## Verification
You can verify the available architectures for the latest release using the following command:

```bash
docker buildx imagetools inspect legato3/phobos-net:latest
```

The output should list both `linux/amd64` and `linux/arm64` under the platforms section.

## Consistency & Stability
Each release candidate is validated on both x86 and ARM platforms to ensure SNMP collection, NetFlow parsing (`nfdump`), and Firewall log ingestion remain authoritative and calm across different hardware environments.
