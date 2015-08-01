#!/bin/sh

while true; do
  filename=$(inotifywait -qe close_write . --include '\.md$' --format '%f')
  markdown < "$filename" > "$(basename "$filename" ".md").html"
  echo "[$(date)] Updated $filename"
done
