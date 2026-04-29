# Push to Docker Hub

```bash
docker build -t c0m4r/paranoya:4.2.0 .
docker build -t c0m4r/paranoya:latest .
docker login
docker push c0m4r/paranoya:4.2.0
docker push c0m4r/paranoya:latest
```

# Push to Github Packages

Generate classic Token (PAT) at https://github.com/settings/tokens

```bash
docker build -t ghcr.io/c0m4r/paranoya:4.2.0 .
docker build -t ghcr.io/c0m4r/paranoya:latest .
export GH_PAT="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
echo $GH_PATH | docker login ghcr.io -u c0m4r --password-stdin
docker push ghcr.io/c0m4r/paranoya:4.2.0
docker push ghcr.io/c0m4r/paranoya:latest
```
