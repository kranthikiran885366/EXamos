#!/usr/bin/env bash

examos_image_output_dir() {
  local root="$1"
  local image_dir="$2"
  local filesystem

  if [[ -n "${EXAMOS_OUTPUT_DIR:-}" ]]; then
    printf '%s\n' "$EXAMOS_OUTPUT_DIR"
    return
  fi

  filesystem="$(stat -f -c %T "$root")"
  case "$filesystem" in
    9p|v9fs|drvfs)
      printf '%s\n' "${HOME}/.local/share/examos/images"
      ;;
    *)
      printf '%s\n' "$image_dir"
      ;;
  esac
}
