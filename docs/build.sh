#!/bin/bash
# Setup python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Cleanup and prepare site directory
rm -r site
mkdir site
cp -r templates/* site/

# Build next version of docs
cat mkdocs.yaml next.yaml | mkdocs build --site-dir site/next --config-file -

idx=0
for config in `ls versioned_docs/*.yaml | sort --version-sort --reverse`; do
  filename=$(basename -- "${config}")
  version="${filename%.*}"

  # Create versioned doc
  cat mkdocs.yaml ${config} | mkdocs build --site-dir site/${version} --config-file -

  idx=$(expr $idx + 1)

  # Update versions.json
  if [ "$idx" -eq "1" ]; then
    cat site/versions.json | jq --arg version "${version}" \
      '.[. | length] |= . + {
        "version": $version,
        "title": $version,
        aliases: [
          "latest"
        ]
      }' | tee site/versions.json > /dev/null

    ln -s "${version}" site/latest
    continue
  fi
  
  cat site/versions.json | jq --arg version "${version}" \
    '.[. | length] |= . + {
      "version": $version,
      "title": $version,
      aliases: []
    }' | tee site/versions.json > /dev/null
done

