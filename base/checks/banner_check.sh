banner_check() {
  if [[ -f /etc/issue.net ]] && grep -q "AUTHORIZED" /etc/issue.net; then
    record "PASS" "banner: /etc/issue.net present"
  else
    record "FAIL" "banner: /etc/issue.net" "missing or no AUTHORIZED text"
  fi
}
