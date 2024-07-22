# Mkdocs setup for oauth2-proxy

For locally testing a change to the docs you need have python installed:

1. (Recommended) Create python venv

```
python3 -m venv venv
source venv/bin/activate
```

2. Install dependencies

```
pip install -r requirements.txt
```

3. Select a version and test
```
cat mkdocs.yaml <version>.yaml | mkdocs <serve/build> --config-file -
```
