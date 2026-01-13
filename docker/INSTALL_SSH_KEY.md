# Install SSH Key on PROX-DOCKER-2

To enable passwordless SSH access, install the SSH public key on the server:

## Quick Install

Run this command (you'll be prompted for password: `c_2580_C`):

```bash
cat ~/.ssh/id_ed25519_192.168.0.73.pub | ssh root@192.168.0.73 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo "SSH key installed successfully"'
```

## Verify

After installation, test the connection:

```bash
ssh -i ~/.ssh/id_ed25519_192.168.0.73 root@192.168.0.73 "echo 'SSH key authentication works!'"
```

If successful, you can now run the deployment script without entering a password.

## Public Key

Your public key is:
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHnWTpSbfnakicXGuJBWak2Tm3obExIK17WEr9Z6g+ah netflow-dashboard-deploy
```
