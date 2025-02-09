# go-tpm-examples

### TPM2 Command Cheat Sheet

1. Check TPM version and capabilities

```bash
tpm2_getcap -l
tpm2_getcap properties-fixed
tpm2_getcap properties-variable
```

2. PCR (Platform Configuration Register) Operations

**Read PCR values**

```bash
tpm2_pcrread sha256:7
```

**Reset PCR values (if allowed)**

```bash
tpm2_pcrreset 7
```

3. Key Management (Primary & Persistent Keys)

**Create a Primary Key**

```bash
tpm2_createprimary -C o -G rsa -g sha256 -c primary.ctx -P <password>
```

**Store Primary Key as Persistent Handle**

```bash
tpm2_evictcontrol -C o -c primary.ctx <persistent-handle>
```

**List Persistent Keys**

```bash
tpm2_getcap handles-persistent
```

**Remove a Persistent Key**

```bash
tpm2_evictcontrol -C o -c <persistent-handle>
```
