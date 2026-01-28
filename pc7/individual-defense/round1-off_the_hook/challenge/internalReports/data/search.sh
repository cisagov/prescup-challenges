#!/bin/bash

TYPE="$1"
QUERY="$2"

case "$TYPE" in
  clients) FILE="/var/data/clients.csv" ;;
  quotes)  FILE="/var/data/quotes.csv" ;;
  invoices) FILE="/var/data/invoices.csv" ;;
  orders)  FILE="/var/data/orders.csv" ;;
  *)  FILE="/var/data/clients.csv" ;;
esac

head -n 1 "$FILE"
tail -n +2 "$FILE" | grep -i "$QUERY"