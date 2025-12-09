python enginsight_tag_manager.py \
  --url https://api.enginsight.com \
  --key-id YOUR_KEY_ID \
  --key-secret YOUR_KEY_SECRET \
  --tag-key PHYSISCHER_STANDORT \
  --tag-value MÜNCHEN \
  --condition "192\.168\.178\."

python enginsight_tag_manager.py \
  --url https://api.enginsight.com \
  --key-id YOUR_KEY_ID \
  --key-secret YOUR_KEY_SECRET \
  --tag-key BETRIEBSSYSTEM \
  --tag-value WINDOWS \
  --condition "\"name\":\s*\"windows\""

python enginsight_tag_manager.py \
  --url https://api.enginsight.com \
  --key-id YOUR_KEY_ID \
  --key-secret YOUR_KEY_SECRET \
  --tag-key HOSTNAME_FILTER \
  --tag-value NGS_HOSTS \
  --condition "\"hostname\":\s*\"[^\"]*ngs[^\"]*\""

python enginsight_tag_manager.py \
  --url https://api.enginsight.com \
  --key-id YOUR_KEY_ID \
  --key-secret YOUR_KEY_SECRET \
  --tag-key TEST \
  --tag-value TEST_VALUE \
  --condition "192\.168\.178\." \
  --dry-run

python enginsight_tag_manager.py \
  --url https://api.enginsight.com \
  --key-id YOUR_KEY_ID \
  --key-secret YOUR_KEY_SECRET \
  --tag-key "UNTERWEGS" \
  --negate-condition \
  --condition "10\.1\.0\."